// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {DkgContract} from "../src/DkgContract.sol";

interface Vm {
    function addr(uint256 privateKey) external pure returns (address);
    function expectEmit(bool checkTopic1, bool checkTopic2, bool checkTopic3, bool checkData, address emitter) external;
    function expectRevert() external;
    function prank(address msgSender) external;
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);
}

contract TestValidatorLookup {
    mapping(address validator => uint64 id) private validatorIds;
    uint64[] private consensus;
    uint64 private epoch = 6;
    bool private inDelay;

    function addTarget(address validator) external {
        uint64 id = uint64(consensus.length + 1);
        validatorIds[validator] = id;
        consensus.push(id);
    }

    function addValidator(address validator) external {
        uint64 id = uint64(consensus.length + 100);
        validatorIds[validator] = id;
    }

    function setEpoch(uint64 epoch_, bool inDelay_) external {
        epoch = epoch_;
        inDelay = inDelay_;
    }

    function getValidatorId(address validator) external view returns (uint64) {
        return validatorIds[validator];
    }

    function getEpoch() external view returns (uint64, bool) {
        return (epoch, inDelay);
    }

    function getConsensusValidatorSet(uint32 startIndex)
        external
        view
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds_)
    {
        return page(consensus, startIndex);
    }

    function getSnapshotValidatorSet(uint32 startIndex)
        external
        pure
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds_)
    {
        return (true, startIndex, new uint64[](0));
    }

    function page(uint64[] storage source, uint32 startIndex)
        private
        view
        returns (bool done, uint32 nextIndex, uint64[] memory values)
    {
        if (startIndex >= source.length) {
            return (true, startIndex, new uint64[](0));
        }
        uint256 end = source.length < uint256(startIndex) + 100 ? source.length : uint256(startIndex) + 100;
        values = new uint64[](end - startIndex);
        for (uint256 i = startIndex; i < end; i++) {
            values[i - startIndex] = source[i];
        }
        return (end == source.length, uint32(end), values);
    }
}

contract DkgContractTest {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint64 private constant EPOCH = 7;

    struct Fixture {
        DkgContract dkg;
        TestValidatorLookup staking;
        address[4] validators;
        uint256[4] qcKeys;
    }

    event PcQcPosted(
        uint64 indexed epoch,
        uint64 indexed sequence,
        uint32 indexed dealer,
        bytes32 digest,
        DkgContract.QcSignature[] signatures
    );
    event BveQcPosted(
        uint64 indexed epoch,
        uint64 indexed sequence,
        uint32 indexed dealer,
        bytes32 digest,
        bytes32 commitmentDigest,
        DkgContract.QcSignature[] signatures
    );
    event DkgResultPosted(
        uint64 indexed epoch, uint64 indexed sequence, bytes32[6] g2x, DkgContract.QcSignature[] signatures
    );
    event PartySetFrozen(uint64 indexed epoch, uint256 partyCount, bytes32 partiesHash);

    function testRegisterStoresTypedPartyRegistration() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory expected = registration(1);
        VM.prank(validator);
        dkg.register(EPOCH, expected);

        require(dkg.registeredPartyCount(EPOCH) == 1, "wrong registration count");
        require(dkg.registeredParty(EPOCH, 0) == validator, "wrong registered party");
        (bool exists, DkgContract.Registration memory stored) = dkg.registrationOf(EPOCH, validator);
        require(exists, "registration missing");
        require(keccak256(abi.encode(stored)) == keccak256(abi.encode(expected)), "wrong registration");
    }

    function testDuplicateRegistrationRevertsWithoutChangingState() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        VM.prank(validator);
        dkg.register(EPOCH, registration(1));
        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, registration(2));
        require(dkg.registeredPartyCount(EPOCH) == 1, "duplicate registration changed state");
    }

    function testMalformedRegistrationCannotOccupyPartySlot() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory malformed = registration(1);
        malformed.qcVerifyingKey.prefix = 4;

        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, malformed);
        require(dkg.registeredPartyCount(EPOCH) == 0, "malformed registration changed state");
    }

    function testRegistrationClosesAtStakingBoundary() external {
        (DkgContract dkg, TestValidatorLookup staking, address validator) = deploySingleRegistrationTarget();
        staking.setEpoch(6, true);
        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, registration(1));
        require(dkg.registeredPartyCount(EPOCH) == 0, "late registration changed state");
    }

    function testUnregisteredStakingCallerCannotWriteDkgState() external {
        TestValidatorLookup staking = new TestValidatorLookup();
        DkgContract dkg = new DkgContract(address(staking));
        address outsider = address(0xBAD);

        VM.expectRevert();
        VM.prank(outsider);
        dkg.register(EPOCH, registration(1));
        require(dkg.registeredPartyCount(EPOCH) == 0, "unregistered caller changed DKG state");
    }

    function testMissingStakingTargetCannotWriteDkgState() external {
        DkgContract dkg = new DkgContract(address(0x1000));

        VM.expectRevert();
        dkg.register(EPOCH, registration(1));
        require(dkg.registeredPartyCount(EPOCH) == 0, "failed staking lookup changed DKG state");
    }

    function testPartyIdsUseSortedEligibleAddresses() external {
        Fixture memory fixture = deploySession();
        postPc(fixture, pcQc(2, 0x11, 1));

        (address[4] memory sorted,) = sortedPartiesAndKeys(fixture);
        require(fixture.dkg.frozenPartyCount(EPOCH) == 4, "wrong frozen party count");
        for (uint32 i = 0; i < 4; i++) {
            require(fixture.dkg.frozenParty(EPOCH, i) == sorted[i], "party order differs from runner");
            (bool exists, uint32 partyId) = fixture.dkg.partyIdOf(EPOCH, sorted[i]);
            require(exists && partyId == i, "wrong party id");
        }
    }

    function testNonTargetValidatorCannotPostProtocolRecord() external {
        Fixture memory fixture = deploySession();
        address outsider = VM.addr(999);
        fixture.staking.addValidator(outsider);
        VM.expectRevert();
        VM.prank(outsider);
        fixture.dkg.postPcQc(EPOCH, pcQc(2, 0x11, 1));
        require(fixture.dkg.recordCount(EPOCH) == 0, "non-target write changed state");
    }

    function testMaximumPartySetCanFreeze() external {
        TestValidatorLookup staking = new TestValidatorLookup();
        DkgContract dkg = new DkgContract(address(staking));
        address first;
        for (uint256 i = 0; i < 200; i++) {
            address validator = address(uint160(1000 - i));
            if (i == 0) {
                first = validator;
            }
            staking.addTarget(validator);
            VM.prank(validator);
            dkg.register(EPOCH, registration(10));
        }
        staking.setEpoch(6, true);

        VM.prank(first);
        dkg.postPcQc(EPOCH, pcQc(1, 0x11, 1));
        require(dkg.frozenPartyCount(EPOCH) == 200, "maximum party set was not frozen");
    }

    function testPcAndBveRecordsAreStoredAsTypedRecords() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory pc = pcQc(2, 0x11, 1);
        DkgContract.BveQc memory bve = bveQc(3, 0x22, 1);

        postPc(fixture, pc);
        postBve(fixture, 0, bve);

        require(fixture.dkg.recordCount(EPOCH) == 2, "wrong record count");
        DkgContract.DkgRecord memory storedPc = fixture.dkg.recordAt(EPOCH, 0);
        DkgContract.DkgRecord memory storedBve = fixture.dkg.recordAt(EPOCH, 1);
        require(storedPc.kind == DkgContract.RecordKind.PcQc, "wrong PC kind");
        require(storedPc.dealer == pc.dealer && storedPc.digest == pc.digest, "wrong PC");
        require(storedPc.signatures.length == 1, "wrong PC witness");
        require(storedBve.kind == DkgContract.RecordKind.BveQc, "wrong BVE kind");
        require(
            storedBve.dealer == bve.dealer && storedBve.digest == bve.digest
                && storedBve.commitmentDigest == bve.commitmentDigest,
            "wrong BVE"
        );
    }

    function testProtocolRecordsEmitTypedEvents() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory pc = pcQc(2, 0x11, 1);
        DkgContract.BveQc memory bve = bveQc(3, 0x22, 1);

        (address[4] memory sorted,) = sortedPartiesAndKeys(fixture);
        address[] memory frozen = new address[](4);
        for (uint256 i = 0; i < 4; i++) {
            frozen[i] = sorted[i];
        }
        VM.expectEmit(true, false, false, true, address(fixture.dkg));
        emit PartySetFrozen(EPOCH, 4, keccak256(abi.encode(frozen)));
        VM.expectEmit(true, true, true, true, address(fixture.dkg));
        emit PcQcPosted(EPOCH, 0, pc.dealer, pc.digest, pc.signatures);
        postPc(fixture, pc);

        VM.expectEmit(true, true, true, true, address(fixture.dkg));
        emit BveQcPosted(EPOCH, 1, bve.dealer, bve.digest, bve.commitmentDigest, bve.signatures);
        postBve(fixture, 0, bve);

        DkgContract.DkgResult memory result = signedResult(fixture, 0x33);
        VM.expectEmit(true, true, false, true, address(fixture.dkg));
        emit DkgResultPosted(EPOCH, 2, result.g2x, result.signatures);
        submitResult(fixture, result);
    }

    function testIdenticalPcQcIsIdempotentAndDifferentWitnessIsRetained() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory original = pcQc(3, 0x11, 1);

        postPc(fixture, original);
        postPc(fixture, original);
        require(fixture.dkg.recordCount(EPOCH) == 1, "identical QC was recorded twice");

        DkgContract.PcQc memory alternateWitness = pcQc(3, 0x11, 2);
        postPc(fixture, alternateWitness);
        require(fixture.dkg.recordCount(EPOCH) == 2, "alternate witness not recorded");
    }

    function testBveQcIsBoundedPerSubmittingValidatorAndDealer() external {
        Fixture memory fixture = deploySession();

        postBve(fixture, 0, bveQc(3, 0x11, 1));
        postBve(fixture, 0, bveQc(3, 0x11, 2));
        require(fixture.dkg.recordCount(EPOCH) == 1, "submitter posted two witnesses for one dealer");

        postBve(fixture, 1, bveQc(3, 0x11, 3));
        require(fixture.dkg.recordCount(EPOCH) == 2, "second validator could not post its witness");
    }

    function testMalformedQcCannotOccupyRecordSlot() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory malformed = pcQc(1, 0x11, 1);
        malformed.signatures[0].signer = 256;

        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.postPcQc(EPOCH, malformed);
        require(fixture.dkg.recordCount(EPOCH) == 0, "malformed QC occupied a record slot");
    }

    function testSubmitResultVerifiesQuorumSignatures() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        submitResult(fixture, result);

        require(fixture.dkg.recordCount(EPOCH) == 1, "wrong record count");
        DkgContract.DkgRecord memory stored = fixture.dkg.recordAt(EPOCH, 0);
        require(stored.kind == DkgContract.RecordKind.DkgResult, "wrong result kind");
        require(stored.resultEpoch == EPOCH, "wrong result epoch");
        require(stored.g2x[0] == result.g2x[0], "wrong result point");

        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
    }

    function testSubmitResultRejectsTamperedPointAndSignature() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        result.g2x[5] = bytes32(uint256(result.g2x[5]) + 1);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
        require(fixture.dkg.recordCount(EPOCH) == 0, "tampered point changed state");

        result = signedResult(fixture, 0x44);
        result.signatures[1].s = bytes32(uint256(result.signatures[1].s) ^ 1);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
        require(fixture.dkg.recordCount(EPOCH) == 0, "invalid signature changed state");
    }

    function testSubmitResultRejectsSubQuorumAndWrongPartyId() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        DkgContract.QcSignature[] memory subQuorum = new DkgContract.QcSignature[](2);
        for (uint256 i = 0; i < 2; i++) {
            subQuorum[i] = result.signatures[i];
        }
        result.signatures = subQuorum;
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);

        result = signedResult(fixture, 0x44);
        result.signatures[2].signer = 3;
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
        require(fixture.dkg.recordCount(EPOCH) == 0, "invalid result changed state");
    }

    function testDoneQcMakesEpochTerminal() external {
        Fixture memory fixture = deploySession();
        submitResult(fixture, signedResult(fixture, 0x44));

        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.postPcQc(EPOCH, pcQc(1, 0x11, 1));
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.postBveQc(EPOCH, bveQc(1, 0x11, 1));
        require(fixture.dkg.recordCount(EPOCH) == 1, "post-DONE QC changed state");
    }

    function testResultEpochMustMatchNamespace() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        result.epoch = EPOCH + 1;
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
        require(fixture.dkg.recordCount(EPOCH) == 0, "mismatched result was stored");
    }

    function deploySession() private returns (Fixture memory fixture) {
        fixture.staking = new TestValidatorLookup();
        fixture.dkg = new DkgContract(address(fixture.staking));
        for (uint256 i = 0; i < 4; i++) {
            fixture.validators[i] = VM.addr(100 + i);
            fixture.qcKeys[i] = i == 3 ? 6 : i + 1;
            fixture.staking.addTarget(fixture.validators[i]);
            VM.prank(fixture.validators[i]);
            fixture.dkg.register(EPOCH, registration(uint8(fixture.qcKeys[i])));
        }
        fixture.staking.setEpoch(6, true);
    }

    function deploySingleRegistrationTarget()
        private
        returns (DkgContract dkg, TestValidatorLookup staking, address validator)
    {
        staking = new TestValidatorLookup();
        validator = VM.addr(100);
        staking.addTarget(validator);
        dkg = new DkgContract(address(staking));
    }

    function postPc(Fixture memory fixture, DkgContract.PcQc memory qc) private {
        VM.prank(fixture.validators[0]);
        fixture.dkg.postPcQc(EPOCH, qc);
    }

    function postBve(Fixture memory fixture, uint256 validatorIndex, DkgContract.BveQc memory qc) private {
        VM.prank(fixture.validators[validatorIndex]);
        fixture.dkg.postBveQc(EPOCH, qc);
    }

    function submitResult(Fixture memory fixture, DkgContract.DkgResult memory result) private {
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
    }

    function registration(uint8 qcKey) private pure returns (DkgContract.Registration memory) {
        return DkgContract.Registration({
            qcVerifyingKey: qcPoint(qcKey),
            receiverPublicKey: point(qcKey + 10),
            receiverKeyImage: point(qcKey + 11),
            proofU0: point(qcKey + 12),
            proofV0: point(qcKey + 13),
            proofZ: bytes32(uint256(qcKey + 14))
        });
    }

    function qcPoint(uint8 key) private pure returns (DkgContract.SecpPoint memory) {
        if (key == 1) {
            return
                DkgContract.SecpPoint({
                    prefix: 2, x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
                });
        }
        if (key == 2) {
            return
                DkgContract.SecpPoint({
                    prefix: 2, x: 0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5
                });
        }
        if (key == 3) {
            return
                DkgContract.SecpPoint({
                    prefix: 2, x: 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9
                });
        }
        if (key == 4) {
            return
                DkgContract.SecpPoint({
                    prefix: 2, x: 0xe493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13
                });
        }
        if (key == 6) {
            return
                DkgContract.SecpPoint({
                    prefix: 3, x: 0xfff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556
                });
        }
        return point(key);
    }

    function point(uint8 seed) private pure returns (DkgContract.SecpPoint memory) {
        return DkgContract.SecpPoint({prefix: 2 + seed % 2, x: bytes32(uint256(seed))});
    }

    function pcQc(uint32 dealer, uint8 digest, uint8 witness) private pure returns (DkgContract.PcQc memory) {
        return DkgContract.PcQc({dealer: dealer, digest: bytes32(uint256(digest)), signatures: signatures(witness)});
    }

    function bveQc(uint32 dealer, uint8 digest, uint8 witness) private pure returns (DkgContract.BveQc memory) {
        return DkgContract.BveQc({
            dealer: dealer,
            digest: bytes32(uint256(digest)),
            commitmentDigest: bytes32(uint256(digest + 1)),
            signatures: signatures(witness)
        });
    }

    function signatures(uint8 witness) private pure returns (DkgContract.QcSignature[] memory result) {
        result = new DkgContract.QcSignature[](1);
        result[0] = DkgContract.QcSignature({signer: 0, r: bytes32(uint256(witness)), s: bytes32(uint256(witness + 1))});
    }

    function signedResult(Fixture memory fixture, uint8 pointByte)
        private
        pure
        returns (DkgContract.DkgResult memory result)
    {
        result.epoch = EPOCH;
        for (uint256 i = 0; i < 6; i++) {
            result.g2x[i] = bytes32(uint256(pointByte) + i);
        }
        (address[4] memory parties, uint256[4] memory keys) = sortedPartiesAndKeys(fixture);
        bytes32 digest = doneQcDigest(EPOCH, result.g2x, parties, keys);
        result.signatures = new DkgContract.QcSignature[](3);
        for (uint32 i = 0; i < 3; i++) {
            (, bytes32 r, bytes32 s) = VM.sign(keys[i], digest);
            result.signatures[i] = DkgContract.QcSignature({signer: i, r: r, s: s});
        }
    }

    function sortedPartiesAndKeys(Fixture memory fixture)
        private
        pure
        returns (address[4] memory parties, uint256[4] memory keys)
    {
        parties = fixture.validators;
        keys = fixture.qcKeys;
        for (uint256 i = 1; i < 4; i++) {
            address party = parties[i];
            uint256 key = keys[i];
            uint256 j = i;
            while (j != 0 && uint160(parties[j - 1]) > uint160(party)) {
                parties[j] = parties[j - 1];
                keys[j] = keys[j - 1];
                j--;
            }
            parties[j] = party;
            keys[j] = key;
        }
    }

    function doneQcDigest(uint64 epoch, bytes32[6] memory g2x, address[4] memory parties, uint256[4] memory keys)
        private
        pure
        returns (bytes32)
    {
        bytes memory session = abi.encodePacked(
            "BTX-DKG/protocol/session-id/v1", _le64(epoch), _le64(4), _le32(0), _le32(1), _le32(2), _le32(3), _le64(4)
        );
        for (uint256 i = 0; i < 4; i++) {
            session = bytes.concat(session, _le64(1));
        }
        session = bytes.concat(session, _le64(1), _le64(3), _le64(3), _le64(4));
        for (uint256 i = 0; i < 4; i++) {
            DkgContract.SecpPoint memory key = qcPoint(uint8(keys[i]));
            session = bytes.concat(session, bytes1(key.prefix), key.x);
        }
        session = bytes.concat(session, _le64(4));
        for (uint256 i = 0; i < 4; i++) {
            session = bytes.concat(session, bytes20(parties[i]));
        }
        bytes32 sessionId = sha256(session);
        return sha256(
            abi.encodePacked(
                "BTX-DKG/protocol/qc-signature/v1",
                _le64(31),
                "BTX-DKG/protocol/dkg-done-qc/v1",
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

    function _le32(uint32 value) private pure returns (bytes4 result) {
        uint32 reversed;
        for (uint256 i = 0; i < 4; i++) {
            reversed |= uint32(uint8(value >> (i * 8))) << uint32((3 - i) * 8);
        }
        return bytes4(reversed);
    }

    function _le64(uint64 value) private pure returns (bytes8 result) {
        uint64 reversed;
        for (uint256 i = 0; i < 8; i++) {
            reversed |= uint64(uint8(value >> (i * 8))) << uint64((7 - i) * 8);
        }
        return bytes8(reversed);
    }
}
