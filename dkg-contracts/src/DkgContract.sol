// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IMonadStaking {
    function getValidatorId(address validator) external returns (uint64);
    function getEpoch() external returns (uint64 epoch, bool inEpochDelayPeriod);
    function getConsensusValidatorSet(uint32 startIndex)
        external
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds);
    function getSnapshotValidatorSet(uint32 startIndex)
        external
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds);
}

/// @notice Typed on-chain ordering and final-result verification for DKG.
///
/// Party identity is frozen at the staking boundary, not supplied by the result
/// submitter. The contract intersects the target epoch's locked validator set
/// with registrations and sorts the resulting addresses ascending. This is the
/// same ordering used by the runner, so PartyId is the address's array index.
///
/// A DKG-DONE QC is accepted only if at least `2 * floor((N - 1) / 3) + 1`
/// distinct PartyIds carry valid secp256k1 signatures over the engine's exact
/// SHA-256 transcript `(epoch, session_id, g2x)`. Once accepted, the epoch is
/// terminal and no further PC or BVE QC can be appended.
contract DkgContract {
    enum RecordKind {
        PcQc,
        BveQc,
        DkgResult
    }

    /// @dev SEC1-compressed secp256k1 point: prefix (2 or 3) plus x-coordinate.
    struct SecpPoint {
        uint8 prefix;
        bytes32 x;
    }

    struct Registration {
        SecpPoint qcVerifyingKey;
        SecpPoint receiverPublicKey;
        SecpPoint receiverKeyImage;
        SecpPoint proofU0;
        SecpPoint proofV0;
        bytes32 proofZ;
    }

    /// @dev Compact secp256k1 signature split into its fixed-width limbs.
    struct QcSignature {
        uint32 signer;
        bytes32 r;
        bytes32 s;
    }

    struct PcQc {
        uint32 dealer;
        bytes32 digest;
        QcSignature[] signatures;
    }

    struct BveQc {
        uint32 dealer;
        bytes32 digest;
        bytes32 commitmentDigest;
        QcSignature[] signatures;
    }

    /// @dev The protocol's serialized BLS12-381 G2 point is exactly 192 bytes.
    struct DkgResult {
        uint64 epoch;
        bytes32[6] g2x;
        QcSignature[] signatures;
    }

    /// @dev Global ordered record. Fields not used by `kind` remain zero.
    struct DkgRecord {
        RecordKind kind;
        uint32 dealer;
        bytes32 digest;
        bytes32 commitmentDigest;
        uint64 resultEpoch;
        bytes32[6] g2x;
        QcSignature[] signatures;
    }

    bytes private constant SESSION_ID_DOMAIN = "BTX-DKG/protocol/session-id/v1";
    bytes private constant STATEMENT_DOMAIN = "BTX-DKG/protocol/qc-signature/v1";
    bytes private constant DKG_DONE_QC_DOMAIN = "BTX-DKG/protocol/dkg-done-qc/v1";
    uint64 private constant DKG_OUTPUT_COUNT = 2;
    uint256 private constant SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 private constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 private constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;
    uint256 private constant MAX_PARTIES = 256;

    address private immutable STAKING;

    mapping(uint64 epoch => DkgRecord[] records) private recordsByEpoch;
    mapping(uint64 epoch => address[] parties) private registeredPartiesByEpoch;
    mapping(uint64 epoch => mapping(address party => Registration registration)) private registrations;
    /// @dev Bit `i` says registration `i` belongs to the frozen target set.
    /// Registrations close before freezing, so one word preserves membership;
    /// canonical addresses are reconstructed and sorted when needed.
    mapping(uint64 epoch => uint256 registrationBitmap) private frozenRegistrationsByEpoch;
    mapping(uint64 epoch => mapping(bytes32 witnessHash => bool seen)) private seenPcQcs;
    mapping(uint64 epoch => mapping(address submitter => mapping(uint32 dealer => bool submitted))) private
        submittedBveQc;
    mapping(uint64 epoch => bool recorded) private resultRecorded;

    event PartyRegistered(uint64 indexed epoch, address indexed party, Registration registration);
    event PartySetFrozen(uint64 indexed epoch, uint256 partyCount, bytes32 partiesHash);
    event PcQcPosted(
        uint64 indexed epoch, uint64 indexed sequence, uint32 indexed dealer, bytes32 digest, QcSignature[] signatures
    );
    event BveQcPosted(
        uint64 indexed epoch,
        uint64 indexed sequence,
        uint32 indexed dealer,
        bytes32 digest,
        bytes32 commitmentDigest,
        QcSignature[] signatures
    );
    event DkgResultPosted(uint64 indexed epoch, uint64 indexed sequence, bytes32[6] g2x, QcSignature[] signatures);

    error AlreadyRegistered(uint64 epoch, address party);
    error DkgAlreadyFinished(uint64 epoch);
    error InvalidDkgResult();
    error InvalidPointPrefix(uint8 prefix);
    error InvalidSecpPoint();
    error MalformedQc();
    error NotEpochParty(uint64 epoch, address caller);
    error NotValidator(address caller);
    error PartySetUnavailable(uint64 epoch);
    error RegistrationClosed(uint64 epoch);
    error ResultAlreadyRecorded(uint64 resultEpoch);
    error StakingLookupFailed();
    error TooManyRegistrations(uint64 epoch);
    error WrongResultEpoch(uint64 expected, uint64 actual);

    constructor(address staking_) {
        STAKING = staking_;
    }

    modifier onlyValidator() {
        _requireValidator();
        _;
    }

    modifier onlyEpochParty(uint64 epoch) {
        _requireEpochParty(epoch);
        _;
    }

    function _requireValidator() private {
        if (_validatorId(msg.sender) == 0) {
            revert NotValidator(msg.sender);
        }
    }

    function _requireEpochParty(uint64 epoch) private returns (address[] memory parties) {
        parties = _partySet(epoch);
        if (_partyId(parties, msg.sender) == type(uint256).max) {
            revert NotEpochParty(epoch, msg.sender);
        }
    }

    function register(uint64 epoch, Registration calldata registration) external onlyValidator {
        _requireRegistrationOpen(epoch);
        if (registrations[epoch][msg.sender].qcVerifyingKey.prefix != 0) {
            revert AlreadyRegistered(epoch, msg.sender);
        }
        if (registeredPartiesByEpoch[epoch].length == MAX_PARTIES) {
            revert TooManyRegistrations(epoch);
        }
        _validateRegistration(registration);
        registrations[epoch][msg.sender] = registration;
        registeredPartiesByEpoch[epoch].push(msg.sender);
        emit PartyRegistered(epoch, msg.sender, registration);
    }

    function postPcQc(uint64 epoch, PcQc calldata qc) external onlyEpochParty(epoch) {
        if (resultRecorded[epoch]) {
            revert DkgAlreadyFinished(epoch);
        }
        _validateQc(qc.dealer, qc.signatures);
        bytes32 witnessHash = keccak256(abi.encode(qc));
        if (seenPcQcs[epoch][witnessHash]) {
            return;
        }
        seenPcQcs[epoch][witnessHash] = true;

        uint64 sequence = _nextSequence(epoch);
        DkgRecord storage record = recordsByEpoch[epoch].push();
        record.kind = RecordKind.PcQc;
        record.dealer = qc.dealer;
        record.digest = qc.digest;
        _copySignatures(record.signatures, qc.signatures);
        emit PcQcPosted(epoch, sequence, qc.dealer, qc.digest, qc.signatures);
    }

    function postBveQc(uint64 epoch, BveQc calldata qc) external onlyEpochParty(epoch) {
        if (resultRecorded[epoch]) {
            revert DkgAlreadyFinished(epoch);
        }
        _validateQc(qc.dealer, qc.signatures);
        if (submittedBveQc[epoch][msg.sender][qc.dealer]) {
            return;
        }
        submittedBveQc[epoch][msg.sender][qc.dealer] = true;

        uint64 sequence = _nextSequence(epoch);
        DkgRecord storage record = recordsByEpoch[epoch].push();
        record.kind = RecordKind.BveQc;
        record.dealer = qc.dealer;
        record.digest = qc.digest;
        record.commitmentDigest = qc.commitmentDigest;
        _copySignatures(record.signatures, qc.signatures);
        emit BveQcPosted(epoch, sequence, qc.dealer, qc.digest, qc.commitmentDigest, qc.signatures);
    }

    function submitResult(uint64 epoch, DkgResult calldata result) external {
        address[] memory parties = _requireEpochParty(epoch);
        if (result.epoch != epoch) {
            revert WrongResultEpoch(epoch, result.epoch);
        }
        if (resultRecorded[epoch]) {
            revert ResultAlreadyRecorded(epoch);
        }
        _validateDkgResult(epoch, result, parties);
        resultRecorded[epoch] = true;

        uint64 sequence = _nextSequence(epoch);
        DkgRecord storage record = recordsByEpoch[epoch].push();
        record.kind = RecordKind.DkgResult;
        record.resultEpoch = result.epoch;
        record.g2x = result.g2x;
        _copySignatures(record.signatures, result.signatures);
        emit DkgResultPosted(epoch, sequence, result.g2x, result.signatures);
    }

    function registrationOf(uint64 epoch, address party)
        external
        view
        returns (bool exists, Registration memory registration)
    {
        registration = registrations[epoch][party];
        exists = registration.qcVerifyingKey.prefix != 0;
    }

    function registeredPartyCount(uint64 epoch) external view returns (uint256) {
        return registeredPartiesByEpoch[epoch].length;
    }

    function registeredParty(uint64 epoch, uint256 index) external view returns (address) {
        return registeredPartiesByEpoch[epoch][index];
    }

    function frozenPartyCount(uint64 epoch) external view returns (uint256) {
        return _partySetView(epoch).length;
    }

    function frozenParty(uint64 epoch, uint256 index) external view returns (address) {
        return _partySetView(epoch)[index];
    }

    function partyIdOf(uint64 epoch, address party) external view returns (bool exists, uint32 partyId) {
        uint256 index = _partyId(_partySetView(epoch), party);
        return (index != type(uint256).max, index == type(uint256).max ? 0 : uint32(index));
    }

    function recordCount(uint64 epoch) external view returns (uint256) {
        return recordsByEpoch[epoch].length;
    }

    function recordAt(uint64 epoch, uint256 index) external view returns (DkgRecord memory) {
        return recordsByEpoch[epoch][index];
    }

    /// @dev Freeze `PartyId -> address` from consensus-owned staking state.
    /// During the boundary delay, consensus is the next epoch and snapshot is
    /// the current epoch. Outside it, consensus is the current epoch. Once
    /// frozen here the mapping remains reconstructible after staking rotates
    /// both sets.
    function _partySet(uint64 epoch) private returns (address[] memory) {
        if (frozenRegistrationsByEpoch[epoch] == 0) {
            return _freezePartySet(epoch);
        }
        return _partySetView(epoch);
    }

    function _freezePartySet(uint64 epoch) private returns (address[] memory parties) {
        uint64[] memory validatorIds = _readValidatorSet(_validatorSetGetter(epoch));
        _sortValidatorIds(validatorIds);

        address[] storage registered = registeredPartiesByEpoch[epoch];
        parties = new address[](registered.length);
        uint256 bitmap;
        uint256 count;
        for (uint256 i = 0; i < registered.length; i++) {
            address party = registered[i];
            if (_containsValidatorId(validatorIds, _validatorId(party))) {
                bitmap |= uint256(1) << i;
                parties[count++] = party;
            }
        }
        if (count < 4 || count > MAX_PARTIES) {
            revert PartySetUnavailable(epoch);
        }

        _sortAddresses(parties, count);
        for (uint256 i = 0; i < count; i++) {
            address party = parties[i];
            if (party == address(0) || (i != 0 && party == parties[i - 1])) {
                revert StakingLookupFailed();
            }
        }
        frozenRegistrationsByEpoch[epoch] = bitmap;

        assembly ("memory-safe") {
            mstore(parties, count)
        }
        emit PartySetFrozen(epoch, count, keccak256(abi.encode(parties)));
    }

    function _partySetView(uint64 epoch) private view returns (address[] memory parties) {
        uint256 bitmap = frozenRegistrationsByEpoch[epoch];
        if (bitmap == 0) {
            return new address[](0);
        }
        address[] storage registered = registeredPartiesByEpoch[epoch];
        parties = new address[](registered.length);
        uint256 count;
        for (uint256 i = 0; i < registered.length; i++) {
            if ((bitmap & (uint256(1) << i)) != 0) {
                parties[count++] = registered[i];
            }
        }
        _sortAddresses(parties, count);
        assembly ("memory-safe") {
            mstore(parties, count)
        }
    }

    function _requireRegistrationOpen(uint64 epoch) private {
        (uint64 currentEpoch, bool inDelay) = _stakingEpoch();
        if (inDelay || currentEpoch == type(uint64).max || epoch != currentEpoch + 1) {
            revert RegistrationClosed(epoch);
        }
    }

    function _validatorSetGetter(uint64 epoch) private returns (bytes4 getter) {
        (uint64 currentEpoch, bool inDelay) = _stakingEpoch();
        if (epoch == currentEpoch) {
            return
                inDelay
                    ? IMonadStaking.getSnapshotValidatorSet.selector
                    : IMonadStaking.getConsensusValidatorSet.selector;
        }
        if (inDelay && currentEpoch != type(uint64).max && epoch == currentEpoch + 1) {
            return IMonadStaking.getConsensusValidatorSet.selector;
        }
        revert PartySetUnavailable(epoch);
    }

    function _stakingEpoch() private returns (uint64 epoch, bool inDelay) {
        bytes memory output = _stakingCall(abi.encodeCall(IMonadStaking.getEpoch, ()));
        if (output.length != 64) {
            revert StakingLookupFailed();
        }
        return abi.decode(output, (uint64, bool));
    }

    function _readValidatorSet(bytes4 getter) private returns (uint64[] memory validatorIds) {
        validatorIds = new uint64[](MAX_PARTIES);
        uint256 count;
        uint32 startIndex;
        while (true) {
            bytes memory output = _stakingCall(abi.encodeWithSelector(getter, startIndex));
            (bool done, uint32 nextIndex, uint64[] memory page) = abi.decode(output, (bool, uint32, uint64[]));
            if (count + page.length > MAX_PARTIES || (!done && nextIndex <= startIndex)) {
                revert StakingLookupFailed();
            }
            for (uint256 i = 0; i < page.length; i++) {
                validatorIds[count++] = page[i];
            }
            if (done) {
                break;
            }
            startIndex = nextIndex;
        }
        assembly ("memory-safe") {
            mstore(validatorIds, count)
        }
    }

    function _validatorId(address validator) private returns (uint64) {
        bytes memory output = _stakingCall(abi.encodeCall(IMonadStaking.getValidatorId, (validator)));
        if (output.length != 32) {
            revert StakingLookupFailed();
        }
        return abi.decode(output, (uint64));
    }

    function _stakingCall(bytes memory input) private returns (bytes memory output) {
        // Native staking has no bytecode and currently accepts CALL, not STATICCALL.
        bool success;
        (success, output) = STAKING.call(input);
        if (!success) {
            revert StakingLookupFailed();
        }
    }

    /// @dev In-place ascending heap sort. Its O(N log N) upper bound keeps the
    /// staking maximum cheap even if validator addresses arrive in reverse order.
    function _sortAddresses(address[] memory parties, uint256 count) private pure {
        if (count < 2) {
            return;
        }
        for (uint256 start = count / 2; start != 0; start--) {
            _siftDown(parties, start - 1, count);
        }
        for (uint256 end = count - 1; end != 0; end--) {
            (parties[0], parties[end]) = (parties[end], parties[0]);
            _siftDown(parties, 0, end);
        }
    }

    function _siftDown(address[] memory parties, uint256 root, uint256 end) private pure {
        while (true) {
            uint256 child = root * 2 + 1;
            if (child >= end) {
                return;
            }
            if (child + 1 < end && uint160(parties[child]) < uint160(parties[child + 1])) {
                child++;
            }
            if (uint160(parties[root]) >= uint160(parties[child])) {
                return;
            }
            (parties[root], parties[child]) = (parties[child], parties[root]);
            root = child;
        }
    }

    function _sortValidatorIds(uint64[] memory validatorIds) private pure {
        uint256 count = validatorIds.length;
        if (count < 2) {
            return;
        }
        for (uint256 start = count / 2; start != 0; start--) {
            _siftDownValidatorIds(validatorIds, start - 1, count);
        }
        for (uint256 end = count - 1; end != 0; end--) {
            (validatorIds[0], validatorIds[end]) = (validatorIds[end], validatorIds[0]);
            _siftDownValidatorIds(validatorIds, 0, end);
        }
    }

    function _siftDownValidatorIds(uint64[] memory validatorIds, uint256 root, uint256 end) private pure {
        while (true) {
            uint256 child = root * 2 + 1;
            if (child >= end) {
                return;
            }
            if (child + 1 < end && validatorIds[child] < validatorIds[child + 1]) {
                child++;
            }
            if (validatorIds[root] >= validatorIds[child]) {
                return;
            }
            (validatorIds[root], validatorIds[child]) = (validatorIds[child], validatorIds[root]);
            root = child;
        }
    }

    function _containsValidatorId(uint64[] memory validatorIds, uint64 validatorId) private pure returns (bool) {
        uint256 low;
        uint256 high = validatorIds.length;
        while (low < high) {
            uint256 middle = (low + high) / 2;
            if (validatorIds[middle] < validatorId) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        return low != validatorIds.length && validatorIds[low] == validatorId;
    }

    function _validateDkgResult(uint64 epoch, DkgResult calldata result, address[] memory parties) private view {
        uint256 partyCount = parties.length;
        uint256 thresholdDegree = (partyCount - 1) / 3;
        uint256 quorum = 2 * thresholdDegree + 1;
        uint256 count = result.signatures.length;
        if (count < quorum || count > partyCount) {
            revert InvalidDkgResult();
        }

        bytes32 digest = _doneQcDigest(epoch, result.g2x, parties);
        uint32 previous;
        for (uint256 i = 0; i < count; i++) {
            QcSignature calldata signature = result.signatures[i];
            if (signature.signer >= partyCount || (i != 0 && signature.signer <= previous)) {
                revert InvalidDkgResult();
            }
            address party = parties[signature.signer];
            address expectedSigner = _secpAddress(registrations[epoch][party].qcVerifyingKey);
            if (!_signatureMatches(expectedSigner, digest, signature.r, signature.s)) {
                revert InvalidDkgResult();
            }
            previous = signature.signer;
        }
    }

    /// @dev Reproduce `DkgSetupContext::assemble` followed by
    /// `dkg_done_qc_statement` from the research engine byte-for-byte.
    function _doneQcDigest(uint64 epoch, bytes32[6] calldata g2x, address[] memory parties)
        private
        view
        returns (bytes32)
    {
        bytes32 sessionId = _deriveSessionId(epoch, parties);
        return sha256(
            abi.encodePacked(
                STATEMENT_DOMAIN,
                _le64(uint64(DKG_DONE_QC_DOMAIN.length)),
                DKG_DONE_QC_DOMAIN,
                _le64(epoch),
                _le64(32),
                sessionId,
                g2x[0],
                g2x[1],
                g2x[2],
                g2x[3],
                g2x[4],
                g2x[5]
            )
        );
    }

    function _deriveSessionId(uint64 epoch, address[] memory parties) private view returns (bytes32) {
        uint256 count = parties.length;
        uint64 thresholdDegree = uint64((count - 1) / 3);
        uint64 quorum = 2 * thresholdDegree + 1;
        uint64 dealerThreshold = DKG_OUTPUT_COUNT + thresholdDegree;
        if (dealerThreshold < quorum) {
            dealerThreshold = quorum;
        }

        // Constant fields occupy 64 bytes; each party contributes id(4),
        // weight(8), compressed QC key(33), and address(20).
        bytes memory preimage = new bytes(SESSION_ID_DOMAIN.length + 64 + count * 65);
        uint256 offset;
        for (uint256 i = 0; i < SESSION_ID_DOMAIN.length; i++) {
            preimage[offset++] = SESSION_ID_DOMAIN[i];
        }
        offset = _writeLe64(preimage, offset, epoch);
        offset = _writeLe64(preimage, offset, uint64(count));
        for (uint32 i = 0; i < count; i++) {
            offset = _writeLe32(preimage, offset, i);
        }
        offset = _writeLe64(preimage, offset, uint64(count));
        for (uint256 i = 0; i < count; i++) {
            offset = _writeLe64(preimage, offset, 1);
        }
        offset = _writeLe64(preimage, offset, thresholdDegree);
        offset = _writeLe64(preimage, offset, quorum);
        offset = _writeLe64(preimage, offset, dealerThreshold);
        offset = _writeLe64(preimage, offset, uint64(count));
        for (uint256 i = 0; i < count; i++) {
            SecpPoint storage key = registrations[epoch][parties[i]].qcVerifyingKey;
            preimage[offset++] = bytes1(key.prefix);
            _writeWord(preimage, offset, key.x);
            offset += 32;
        }
        offset = _writeLe64(preimage, offset, uint64(count));
        for (uint256 i = 0; i < count; i++) {
            _writeAddress(preimage, offset, parties[i]);
            offset += 20;
        }
        assert(offset == preimage.length);
        return sha256(preimage);
    }

    function _signatureMatches(address expected, bytes32 digest, bytes32 r, bytes32 s) private pure returns (bool) {
        uint256 rValue = uint256(r);
        uint256 sValue = uint256(s);
        if (expected == address(0) || rValue == 0 || rValue >= SECP256K1_N || sValue == 0 || sValue > SECP256K1_HALF_N)
        {
            return false;
        }
        return ecrecover(digest, 27, r, s) == expected || ecrecover(digest, 28, r, s) == expected;
    }

    function _secpAddress(SecpPoint storage point) private view returns (address) {
        uint256 x = uint256(point.x);
        if ((point.prefix != 2 && point.prefix != 3) || x >= SECP256K1_P) {
            revert InvalidSecpPoint();
        }
        uint256 ySquared = addmod(mulmod(mulmod(x, x, SECP256K1_P), x, SECP256K1_P), 7, SECP256K1_P);
        uint256 y = _modExp(ySquared, SECP256K1_SQRT_EXPONENT, SECP256K1_P);
        if (mulmod(y, y, SECP256K1_P) != ySquared) {
            revert InvalidSecpPoint();
        }
        if ((y & 1) != (point.prefix & 1)) {
            y = SECP256K1_P - y;
        }
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes32(x), bytes32(y))))));
    }

    function _modExp(uint256 base, uint256 exponent, uint256 modulus) private view returns (uint256 result) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exponent, modulus);
        (bool success, bytes memory output) = address(0x05).staticcall(input);
        if (!success || output.length != 32) {
            revert InvalidSecpPoint();
        }
        result = abi.decode(output, (uint256));
    }

    function _nextSequence(uint64 epoch) private view returns (uint64 sequence) {
        uint256 length = recordsByEpoch[epoch].length;
        if (length > type(uint64).max) {
            revert MalformedQc();
        }
        return uint64(length);
    }

    function _validateRegistration(Registration calldata registration) private pure {
        _validatePoint(registration.qcVerifyingKey);
        _validatePoint(registration.receiverPublicKey);
        _validatePoint(registration.receiverKeyImage);
        _validatePoint(registration.proofU0);
        _validatePoint(registration.proofV0);
    }

    function _validatePoint(SecpPoint calldata point) private pure {
        if (point.prefix != 2 && point.prefix != 3) {
            revert InvalidPointPrefix(point.prefix);
        }
    }

    function _validateQc(uint32 dealer, QcSignature[] calldata signatures) private pure {
        if (dealer >= MAX_PARTIES) {
            revert MalformedQc();
        }
        _validateSignatures(signatures);
    }

    function _validateSignatures(QcSignature[] calldata signatures) private pure {
        uint256 count = signatures.length;
        if (count == 0 || count > MAX_PARTIES) {
            revert MalformedQc();
        }
        uint32 previous;
        for (uint256 i = 0; i < count; i++) {
            uint32 signer = signatures[i].signer;
            if (signer >= MAX_PARTIES || (i != 0 && signer <= previous)) {
                revert MalformedQc();
            }
            previous = signer;
        }
    }

    function _copySignatures(QcSignature[] storage target, QcSignature[] calldata source) private {
        for (uint256 i = 0; i < source.length; i++) {
            target.push(source[i]);
        }
    }

    function _writeLe32(bytes memory output, uint256 offset, uint32 value) private pure returns (uint256) {
        for (uint256 i = 0; i < 4; i++) {
            output[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
        return offset + 4;
    }

    function _writeLe64(bytes memory output, uint256 offset, uint64 value) private pure returns (uint256) {
        for (uint256 i = 0; i < 8; i++) {
            output[offset + i] = bytes1(uint8(value >> (i * 8)));
        }
        return offset + 8;
    }

    function _le64(uint64 value) private pure returns (bytes8 result) {
        uint64 reversed;
        for (uint256 i = 0; i < 8; i++) {
            reversed |= uint64(uint8(value >> (i * 8))) << uint64((7 - i) * 8);
        }
        return bytes8(reversed);
    }

    function _writeWord(bytes memory output, uint256 offset, bytes32 value) private pure {
        assembly ("memory-safe") {
            mstore(add(add(output, 0x20), offset), value)
        }
    }

    function _writeAddress(bytes memory output, uint256 offset, address value) private pure {
        assembly ("memory-safe") {
            mstore(add(add(output, 0x20), offset), shl(96, value))
        }
    }

    function _partyId(address[] memory parties, address party) private pure returns (uint256) {
        uint256 low;
        uint256 high = parties.length;
        while (low < high) {
            uint256 middle = (low + high) / 2;
            address candidate = parties[middle];
            if (uint160(candidate) < uint160(party)) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if (low == parties.length || parties[low] != party) {
            return type(uint256).max;
        }
        return low;
    }
}
