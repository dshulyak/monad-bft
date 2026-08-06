// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IMonadStaking {
    function getValidator(uint64 validatorId) external;
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
/// Party identity is derived from staking, not supplied by the result submitter.
/// The contract intersects the target epoch's validator set with registrations
/// while preserving validator-set order. The runner uses the same stable filter,
/// so PartyId is the address's compact array index.
///
/// A DKG-DONE QC is accepted only if distinct PartyIds with strictly more than
/// two thirds of the target epoch's whole-MON voting weight
/// carry valid secp256k1 signatures over the engine's exact SHA-256 transcript
/// `(epoch, session_id, g2x)`. Once accepted, the epoch is terminal and no
/// further PC or BVE QC can be appended.
contract DkgContract {
    enum RecordKind {
        PcQc,
        BveQc,
        DkgResult
    }

    enum ValidatorSetKind {
        Consensus,
        Snapshot
    }

    /// @dev SEC1-compressed secp256k1 point: prefix (2 or 3) plus x-coordinate.
    struct SecpPoint {
        uint8 prefix;
        bytes32 x;
    }

    struct Registration {
        address qcVerifier;
        SecpPoint receiverPublicKey;
        uint32 receiverProofNonce;
        bytes32 receiverProofR;
        bytes32 receiverProofS;
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
        bytes32 sessionId;
        bytes32[6] g2x;
        QcSignature[] signatures;
    }

    struct RecordRef {
        RecordKind kind;
        uint64 index;
    }

    struct SequencedPcQc {
        uint64 sequence;
        PcQc qc;
    }

    struct SequencedBveQc {
        uint64 sequence;
        BveQc qc;
    }

    struct SequencedDkgResult {
        uint64 sequence;
        DkgResult result;
    }

    struct RecordPage {
        uint64 total;
        uint64 next;
        SequencedPcQc[] pcQcs;
        SequencedBveQc[] bveQcs;
        SequencedDkgResult[] results;
    }

    struct RecordCounts {
        uint256 pc;
        uint256 bve;
        uint256 result;
    }

    bytes private constant STATEMENT_DOMAIN = "BTX-DKG/protocol/qc-signature/v1";
    bytes private constant DKG_DONE_QC_DOMAIN = "BTX-DKG/protocol/dkg-done-qc/v1";
    bytes private constant RECEIVER_KEY_PROOF_DOMAIN = "BTX-DKG/protocol/receiver-key-pop/v1";
    uint256 private constant SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    uint256 private constant SECP256K1_SQRT_EXPONENT =
        0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C;
    uint256 private constant WEI_PER_MON = 1 ether;
    IMonadStaking private immutable STAKING;

    mapping(uint64 epoch => RecordRef[] records) private recordsByEpoch;
    mapping(uint64 epoch => PcQc[] records) private pcQcsByEpoch;
    mapping(uint64 epoch => BveQc[] records) private bveQcsByEpoch;
    mapping(uint64 epoch => DkgResult[] records) private resultsByEpoch;
    mapping(uint64 epoch => uint256 count) private registrationCountByEpoch;
    mapping(uint64 epoch => mapping(address party => Registration registration)) private registrations;
    mapping(uint64 epoch => mapping(uint64 validatorId => address party)) private registeredPartyByValidatorId;
    mapping(uint64 epoch => mapping(address submitter => mapping(uint32 dealer => bool submitted))) private
        submittedPcQc;
    mapping(uint64 epoch => mapping(address submitter => mapping(uint32 dealer => bool submitted))) private
        submittedBveQc;
    mapping(uint64 epoch => bool recorded) private resultRecorded;

    event PartyRegistered(uint64 indexed epoch, address indexed party, Registration registration);
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
    event DkgResultPosted(
        uint64 indexed epoch, uint64 indexed sequence, bytes32 sessionId, bytes32[6] g2x, QcSignature[] signatures
    );

    error AlreadyRegistered(uint64 epoch, address party);
    error DkgAlreadyFinished(uint64 epoch);
    error InvalidDkgResult();
    error InvalidSecpPoint();
    error InvalidQcVerifier();
    error InvalidReceiverProof();
    error MalformedQc();
    error InvalidRecordPage(uint64 start, uint32 limit);
    error NotEpochParty(uint64 epoch, address caller);
    error NotValidator(address caller);
    error PartySetUnavailable(uint64 epoch);
    error RegistrationClosed(uint64 epoch);
    error ResultAlreadyRecorded(uint64 resultEpoch);
    error StakingLookupFailed();

    constructor(address staking_) {
        STAKING = IMonadStaking(staking_);
    }

    function _requireEpochParty(uint64 epoch) private returns (address[] memory parties) {
        parties = _partySet(epoch);
        if (!_contains(parties, msg.sender)) {
            revert NotEpochParty(epoch, msg.sender);
        }
    }

    function register(uint64 epoch, Registration calldata registration) external {
        _requireRegistrationOpen(epoch);
        uint64 validatorId = _validatorId(msg.sender);
        if (validatorId == 0) {
            revert NotValidator(msg.sender);
        }
        if (registrations[epoch][msg.sender].qcVerifier != address(0)) {
            revert AlreadyRegistered(epoch, msg.sender);
        }
        if (registeredPartyByValidatorId[epoch][validatorId] != address(0)) {
            revert AlreadyRegistered(epoch, msg.sender);
        }
        _validateRegistration(epoch, msg.sender, registration);
        registrations[epoch][msg.sender] = registration;
        registeredPartyByValidatorId[epoch][validatorId] = msg.sender;
        registrationCountByEpoch[epoch]++;
        emit PartyRegistered(epoch, msg.sender, registration);
    }

    function postPcQc(uint64 epoch, PcQc calldata qc) external {
        address[] memory parties = _requireEpochParty(epoch);
        if (resultRecorded[epoch]) {
            revert DkgAlreadyFinished(epoch);
        }
        _validateQc(qc.dealer, qc.signatures, parties.length);
        if (submittedPcQc[epoch][msg.sender][qc.dealer]) {
            return;
        }
        submittedPcQc[epoch][msg.sender][qc.dealer] = true;

        uint64 sequence = _nextSequence(epoch);
        uint64 index = _recordIndex(pcQcsByEpoch[epoch].length);
        PcQc storage record = pcQcsByEpoch[epoch].push();
        record.dealer = qc.dealer;
        record.digest = qc.digest;
        _copySignatures(record.signatures, qc.signatures);
        recordsByEpoch[epoch].push(RecordRef({kind: RecordKind.PcQc, index: index}));
        emit PcQcPosted(epoch, sequence, qc.dealer, qc.digest, qc.signatures);
    }

    function postBveQc(uint64 epoch, BveQc calldata qc) external {
        address[] memory parties = _requireEpochParty(epoch);
        if (resultRecorded[epoch]) {
            revert DkgAlreadyFinished(epoch);
        }
        _validateQc(qc.dealer, qc.signatures, parties.length);
        if (submittedBveQc[epoch][msg.sender][qc.dealer]) {
            return;
        }
        submittedBveQc[epoch][msg.sender][qc.dealer] = true;

        uint64 sequence = _nextSequence(epoch);
        uint64 index = _recordIndex(bveQcsByEpoch[epoch].length);
        BveQc storage record = bveQcsByEpoch[epoch].push();
        record.dealer = qc.dealer;
        record.digest = qc.digest;
        record.commitmentDigest = qc.commitmentDigest;
        _copySignatures(record.signatures, qc.signatures);
        recordsByEpoch[epoch].push(RecordRef({kind: RecordKind.BveQc, index: index}));
        emit BveQcPosted(epoch, sequence, qc.dealer, qc.digest, qc.commitmentDigest, qc.signatures);
    }

    function submitResult(uint64 epoch, DkgResult calldata result) external {
        address[] memory parties = _requireEpochParty(epoch);
        if (resultRecorded[epoch]) {
            revert ResultAlreadyRecorded(epoch);
        }
        _validateDkgResult(epoch, result, parties);
        resultRecorded[epoch] = true;

        uint64 sequence = _nextSequence(epoch);
        uint64 index = _recordIndex(resultsByEpoch[epoch].length);
        DkgResult storage record = resultsByEpoch[epoch].push();
        record.sessionId = result.sessionId;
        record.g2x = result.g2x;
        _copySignatures(record.signatures, result.signatures);
        recordsByEpoch[epoch].push(RecordRef({kind: RecordKind.DkgResult, index: index}));
        emit DkgResultPosted(epoch, sequence, result.sessionId, result.g2x, result.signatures);
    }

    function registrationOf(uint64 epoch, address party)
        external
        view
        returns (bool exists, Registration memory registration)
    {
        registration = registrations[epoch][party];
        exists = registration.qcVerifier != address(0);
    }

    function records(uint64 epoch, uint64 start, uint32 limit) external view returns (RecordPage memory page) {
        uint256 total = recordsByEpoch[epoch].length;
        if (start > total || limit == 0) {
            revert InvalidRecordPage(start, limit);
        }
        uint256 requestedEnd = uint256(start) + limit;
        uint256 end = requestedEnd < total ? requestedEnd : total;
        RecordCounts memory counts = _recordCounts(epoch, start, end);

        page.total = _recordIndex(total);
        page.next = _recordIndex(end);
        page.pcQcs = new SequencedPcQc[](counts.pc);
        page.bveQcs = new SequencedBveQc[](counts.bve);
        page.results = new SequencedDkgResult[](counts.result);
        _fillRecordPage(epoch, start, end, page);
    }

    function _recordCounts(uint64 epoch, uint256 start, uint256 end) private view returns (RecordCounts memory counts) {
        RecordRef[] storage ordered = recordsByEpoch[epoch];
        for (uint256 sequence = start; sequence < end; sequence++) {
            RecordKind kind = ordered[sequence].kind;
            if (kind == RecordKind.PcQc) {
                counts.pc++;
            } else if (kind == RecordKind.BveQc) {
                counts.bve++;
            } else {
                counts.result++;
            }
        }
    }

    function _fillRecordPage(uint64 epoch, uint256 start, uint256 end, RecordPage memory page) private view {
        RecordRef[] storage ordered = recordsByEpoch[epoch];
        RecordCounts memory cursor;
        for (uint256 sequence = start; sequence < end; sequence++) {
            RecordRef storage recordRef = ordered[sequence];
            uint64 recordSequence = _recordIndex(sequence);
            if (recordRef.kind == RecordKind.PcQc) {
                page.pcQcs[cursor.pc].sequence = recordSequence;
                page.pcQcs[cursor.pc].qc = pcQcsByEpoch[epoch][recordRef.index];
                cursor.pc++;
            } else if (recordRef.kind == RecordKind.BveQc) {
                page.bveQcs[cursor.bve].sequence = recordSequence;
                page.bveQcs[cursor.bve].qc = bveQcsByEpoch[epoch][recordRef.index];
                cursor.bve++;
            } else {
                page.results[cursor.result].sequence = recordSequence;
                page.results[cursor.result].result = resultsByEpoch[epoch][recordRef.index];
                cursor.result++;
            }
        }
    }

    /// @dev Derive `PartyId -> address` by stable-filtering registrations through
    /// the target epoch's canonical staking order. The staking window is checked
    /// on every use, so no historical party-set cache is required.
    function _partySet(uint64 epoch) private returns (address[] memory parties) {
        ValidatorSetKind kind = _validatorSetKind(epoch);
        parties = new address[](registrationCountByEpoch[epoch]);
        uint256 count;
        uint32 startIndex;
        while (true) {
            (bool done, uint32 nextIndex, uint64[] memory validatorIds) = _readValidatorPage(kind, startIndex);
            if (!done && nextIndex <= startIndex) {
                revert StakingLookupFailed();
            }
            for (uint256 i = 0; i < validatorIds.length; i++) {
                uint64 validatorId = validatorIds[i];
                if (validatorId == 0) {
                    revert StakingLookupFailed();
                }
                address party = registeredPartyByValidatorId[epoch][validatorId];
                if (party == address(0)) {
                    continue;
                }
                if (count == parties.length) {
                    revert StakingLookupFailed();
                }
                parties[count++] = party;
            }
            if (done) {
                break;
            }
            startIndex = nextIndex;
        }
        if (count == 0) {
            revert PartySetUnavailable(epoch);
        }
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

    function _validatorSetKind(uint64 epoch) private returns (ValidatorSetKind) {
        (uint64 currentEpoch, bool inDelay) = _stakingEpoch();
        if (epoch == currentEpoch) {
            return inDelay ? ValidatorSetKind.Snapshot : ValidatorSetKind.Consensus;
        }
        if (inDelay && currentEpoch != type(uint64).max && epoch == currentEpoch + 1) {
            return ValidatorSetKind.Consensus;
        }
        revert PartySetUnavailable(epoch);
    }

    function _stakingEpoch() private returns (uint64 epoch, bool inDelay) {
        try STAKING.getEpoch() returns (uint64 currentEpoch, bool inEpochDelayPeriod) {
            return (currentEpoch, inEpochDelayPeriod);
        } catch {
            revert StakingLookupFailed();
        }
    }

    function _readValidatorPage(ValidatorSetKind kind, uint32 startIndex)
        private
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds)
    {
        if (kind == ValidatorSetKind.Consensus) {
            try STAKING.getConsensusValidatorSet(startIndex) returns (
                bool pageDone, uint32 followingIndex, uint64[] memory page
            ) {
                return (pageDone, followingIndex, page);
            } catch {
                revert StakingLookupFailed();
            }
        }
        try STAKING.getSnapshotValidatorSet(startIndex) returns (
            bool pageDone, uint32 followingIndex, uint64[] memory page
        ) {
            return (pageDone, followingIndex, page);
        } catch {
            revert StakingLookupFailed();
        }
    }

    function _validatorId(address validator) private returns (uint64) {
        try STAKING.getValidatorId(validator) returns (uint64 validatorId) {
            return validatorId;
        } catch {
            revert StakingLookupFailed();
        }
    }

    function _validateDkgResult(uint64 epoch, DkgResult calldata result, address[] memory parties) private {
        if (!_signaturesAreCanonical(result.signatures, parties.length)) {
            revert InvalidDkgResult();
        }

        // DONE is only valid while staking still exposes this epoch. Consensus
        // holds an upcoming/current set; after its ending boundary the same set
        // is retained in snapshot until the following epoch begins.
        uint256[] memory votingWeights = _votingWeights(parties, _validatorSetKind(epoch));

        // A quorum signs the supplied session id together with the epoch and
        // result. At most f Byzantine signers cannot authenticate a session id
        // that the honest engine did not derive for this party set.
        bytes32 digest = _doneQcDigest(epoch, result.sessionId, result.g2x);
        if (
            _signedResultVotingWeight(epoch, result.signatures, parties, votingWeights, digest)
                < _votingWeightQuorum(votingWeights)
        ) {
            revert InvalidDkgResult();
        }
    }

    function _signedResultVotingWeight(
        uint64 epoch,
        QcSignature[] calldata signatures,
        address[] memory parties,
        uint256[] memory votingWeights,
        bytes32 digest
    ) private view returns (uint256 signedVotingWeight) {
        for (uint256 i = 0; i < signatures.length; i++) {
            QcSignature calldata signature = signatures[i];
            if (!_signatureMatches(
                    registrations[epoch][parties[signature.signer]].qcVerifier, digest, signature.r, signature.s
                )) {
                revert InvalidDkgResult();
            }
            signedVotingWeight += votingWeights[signature.signer];
        }
    }

    function _votingWeightQuorum(uint256[] memory votingWeights) private pure returns (uint256) {
        uint256 totalVotingWeight;
        for (uint256 i = 0; i < votingWeights.length; i++) {
            totalVotingWeight += votingWeights[i];
        }
        return totalVotingWeight - (totalVotingWeight - 1) / 3;
    }

    function _validatorStake(uint64 validatorId, ValidatorSetKind kind) private returns (uint256) {
        (bool success, bytes memory output) =
            address(STAKING).call(abi.encodeWithSelector(IMonadStaking.getValidator.selector, validatorId));
        // The staking precompile returns ten fixed words followed by two dynamic
        // key fields. Consensus and snapshot stake are fixed words 6 and 8.
        if (!success || output.length < 320) {
            revert StakingLookupFailed();
        }
        uint256 consensusStake;
        uint256 snapshotStake;
        assembly ("memory-safe") {
            consensusStake := mload(add(output, 0xe0))
            snapshotStake := mload(add(output, 0x120))
        }
        return kind == ValidatorSetKind.Consensus ? consensusStake : snapshotStake;
    }

    function _votingWeights(address[] memory parties, ValidatorSetKind kind)
        private
        returns (uint256[] memory weights)
    {
        weights = new uint256[](parties.length);
        for (uint256 i = 0; i < parties.length; i++) {
            uint64 validatorId = _validatorId(parties[i]);
            if (validatorId == 0) {
                revert StakingLookupFailed();
            }
            weights[i] = _votingWeight(_validatorStake(validatorId, kind));
        }
    }

    function _votingWeight(uint256 stake) private pure returns (uint256 weight) {
        if (stake == 0) {
            revert StakingLookupFailed();
        }
        weight = stake / WEI_PER_MON;
        if (stake % WEI_PER_MON >= WEI_PER_MON / 2) {
            weight++;
        }
        // Active validators are far above one MON. Rejecting zero also prevents
        // quorum arithmetic from accepting a party omitted by the Rust engine.
        if (weight == 0) {
            revert StakingLookupFailed();
        }
    }

    /// @dev Reproduce the research engine's `dkg_done_qc_statement`.
    function _doneQcDigest(uint64 epoch, bytes32 sessionId, bytes32[6] calldata g2x) private pure returns (bytes32) {
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

    function _signatureMatches(address expected, bytes32 digest, bytes32 r, bytes32 s) private pure returns (bool) {
        if (expected == address(0) || uint256(s) > SECP256K1_HALF_N) {
            return false;
        }
        return ecrecover(digest, 27, r, s) == expected || ecrecover(digest, 28, r, s) == expected;
    }

    function _secpAddress(SecpPoint calldata point) private view returns (address) {
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
        return _recordIndex(recordsByEpoch[epoch].length);
    }

    function _recordIndex(uint256 index) private pure returns (uint64) {
        if (index > type(uint64).max) {
            revert MalformedQc();
        }
        return uint64(index);
    }

    function _validateRegistration(uint64 epoch, address party, Registration calldata registration) private view {
        if (registration.qcVerifier == address(0)) {
            revert InvalidQcVerifier();
        }
        address receiverVerifier = _secpAddress(registration.receiverPublicKey);
        bytes32 digest = _receiverKeyProofDigest(epoch, party, registration);
        // The proof is checked before storage so the contract and engine derive
        // the same eligible set even when a validator submits malformed keys.
        if (!_signatureMatches(receiverVerifier, digest, registration.receiverProofR, registration.receiverProofS)) {
            revert InvalidReceiverProof();
        }
    }

    function _receiverKeyProofDigest(uint64 epoch, address party, Registration calldata registration)
        private
        pure
        returns (bytes32)
    {
        return sha256(
            abi.encodePacked(
                RECEIVER_KEY_PROOF_DOMAIN,
                party,
                _le64(epoch),
                registration.qcVerifier,
                registration.receiverPublicKey.prefix,
                registration.receiverPublicKey.x,
                _le32(registration.receiverProofNonce)
            )
        );
    }

    function _validateQc(uint32 dealer, QcSignature[] calldata signatures, uint256 partyCount) private pure {
        if (dealer >= partyCount || !_signaturesAreCanonical(signatures, partyCount)) {
            revert MalformedQc();
        }
    }

    function _signaturesAreCanonical(QcSignature[] calldata signatures, uint256 partyCount)
        private
        pure
        returns (bool)
    {
        uint256 count = signatures.length;
        if (count == 0 || count > partyCount) {
            return false;
        }
        uint32 previous;
        for (uint256 i = 0; i < count; i++) {
            uint32 signer = signatures[i].signer;
            if (signer >= partyCount || (i != 0 && signer <= previous)) {
                return false;
            }
            previous = signer;
        }
        return true;
    }

    function _copySignatures(QcSignature[] storage target, QcSignature[] calldata source) private {
        for (uint256 i = 0; i < source.length; i++) {
            target.push(source[i]);
        }
    }

    function _le64(uint64 value) private pure returns (bytes8 result) {
        uint64 reversed;
        for (uint256 i = 0; i < 8; i++) {
            reversed |= uint64(uint8(value >> (i * 8))) << uint64((7 - i) * 8);
        }
        return bytes8(reversed);
    }

    function _le32(uint32 value) private pure returns (bytes4 result) {
        uint32 reversed;
        for (uint256 i = 0; i < 4; i++) {
            reversed |= uint32(uint8(value >> (i * 8))) << uint32((3 - i) * 8);
        }
        return bytes4(reversed);
    }

    function _contains(address[] memory parties, address party) private pure returns (bool) {
        for (uint256 i = 0; i < parties.length; i++) {
            if (parties[i] == party) {
                return true;
            }
        }
        return false;
    }
}
