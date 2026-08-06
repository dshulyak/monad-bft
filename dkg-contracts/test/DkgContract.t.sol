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
    uint256 private constant WEI_PER_MON = 1 ether;

    mapping(address validator => uint64 id) private validatorIds;
    mapping(uint64 validatorId => uint256 stake) private consensusStakes;
    mapping(uint64 validatorId => uint256 stake) private snapshotStakes;
    uint64[] private consensus;
    uint64[] private snapshot;
    uint64 private epoch = 6;
    uint64 private nextValidatorId = 1;
    bool private inDelay;

    function addTarget(address validator) external {
        uint64 id = nextValidatorId++;
        validatorIds[validator] = id;
        consensusStakes[id] = WEI_PER_MON;
        snapshotStakes[id] = WEI_PER_MON;
        consensus.push(id);
        snapshot.push(id);
    }

    function addValidator(address validator) external {
        uint64 id = nextValidatorId++;
        validatorIds[validator] = id;
    }

    function setEpoch(uint64 epoch_, bool inDelay_) external {
        epoch = epoch_;
        inDelay = inDelay_;
    }

    function setStake(address validator, uint256 stake) external {
        uint64 validatorId = validatorIds[validator];
        consensusStakes[validatorId] = stake;
        snapshotStakes[validatorId] = stake;
    }

    function setConsensusStake(address validator, uint256 stake) external {
        consensusStakes[validatorIds[validator]] = stake;
    }

    function setSnapshotStake(address validator, uint256 stake) external {
        snapshotStakes[validatorIds[validator]] = stake;
    }

    function getValidatorId(address validator) external view returns (uint64) {
        return validatorIds[validator];
    }

    function getValidator(uint64 validatorId) external view {
        uint256 consensusStake = consensusStakes[validatorId];
        uint256 snapshotStake = snapshotStakes[validatorId];
        assembly ("memory-safe") {
            let output := mload(0x40)
            mstore(add(output, 0x40), consensusStake)
            mstore(add(output, 0xc0), consensusStake)
            mstore(add(output, 0x100), snapshotStake)
            return(output, 0x140)
        }
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
        view
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds_)
    {
        return page(snapshot, startIndex);
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
        uint64 indexed epoch,
        uint64 indexed sequence,
        bytes32 sessionId,
        bytes32[6] g2x,
        DkgContract.QcSignature[] signatures
    );

    function testRegisterStoresTypedPartyRegistration() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory expected = registration(validator, 1);
        VM.prank(validator);
        dkg.register(EPOCH, expected);

        (bool exists, DkgContract.Registration memory stored) = dkg.registrationOf(EPOCH, validator);
        require(exists, "registration missing");
        require(keccak256(abi.encode(stored)) == keccak256(abi.encode(expected)), "wrong registration");
    }

    function testReceiverProofMatchesRustVector() external pure {
        address validator = VM.addr(100);
        DkgContract.Registration memory record = registration(validator, 1);
        require(
            receiverKeyProofDigest(validator, record.qcVerifier, record.receiverPublicKey, record.receiverProofNonce)
                == 0x336475c01467c96c760ff8210e598f3e07d0004a6e4bd19c2dcede6e5bad65f1,
            "receiver proof transcript differs from Rust"
        );
        require(
            record.receiverProofR == 0xc76aa5c99ef3e13e46cb5fe8a8cbed3c6dbe0d2bae141f8e430ea0c14dd57198
                && record.receiverProofS == 0x624d2e80fe71603bb686e783debbae1b4b59d339f2b526a0d3b47b527abf08c1,
            "receiver proof signature differs from Rust"
        );
    }

    function testDuplicateRegistrationReverts() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory first = registration(validator, 1);
        VM.prank(validator);
        dkg.register(EPOCH, first);
        DkgContract.Registration memory second = registration(validator, 2);
        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, second);
    }

    function testMalformedRegistrationCannotOccupyPartySlot() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory malformed = registration(validator, 1);
        malformed.qcVerifier = address(0);

        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, malformed);
    }

    function testInvalidReceiverProofCannotOccupyPartySlot() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory malformed = registration(validator, 1);
        malformed.receiverProofR = bytes32(uint256(malformed.receiverProofR) ^ 1);

        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, malformed);
        (bool exists,) = dkg.registrationOf(EPOCH, validator);
        require(!exists, "invalid receiver proof was stored");
    }

    function testReceiverProofBindsQcVerifier() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory malformed = registration(validator, 1);
        malformed.qcVerifier = VM.addr(2);

        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, malformed);
    }

    function testReceiverProofBindsValidator() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory copied = registration(VM.addr(101), 1);

        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, copied);
    }

    function testRegistrationRejectsPointOutsideSecpField() external {
        (DkgContract dkg,, address validator) = deploySingleRegistrationTarget();
        DkgContract.Registration memory malformed = registration(validator, 1);
        malformed.receiverPublicKey.x = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;

        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, malformed);
    }

    function testRegistrationClosesAtStakingBoundary() external {
        (DkgContract dkg, TestValidatorLookup staking, address validator) = deploySingleRegistrationTarget();
        staking.setEpoch(6, true);
        DkgContract.Registration memory record = registration(validator, 1);
        VM.expectRevert();
        VM.prank(validator);
        dkg.register(EPOCH, record);
    }

    function testUnregisteredStakingCallerCannotWriteDkgState() external {
        TestValidatorLookup staking = new TestValidatorLookup();
        DkgContract dkg = new DkgContract(address(staking));
        address outsider = address(0xBAD);

        DkgContract.Registration memory record = registration(outsider, 1);
        VM.expectRevert();
        VM.prank(outsider);
        dkg.register(EPOCH, record);
    }

    function testMissingStakingTargetCannotWriteDkgState() external {
        DkgContract dkg = new DkgContract(address(0x1000));

        DkgContract.Registration memory record = registration(address(this), 1);
        VM.expectRevert();
        dkg.register(EPOCH, record);
    }

    function testPartyCountCompactsMissingRegistrations() external {
        TestValidatorLookup staking = new TestValidatorLookup();
        DkgContract dkg = new DkgContract(address(staking));
        address[5] memory validators;
        for (uint256 i = 0; i < validators.length; i++) {
            validators[i] = VM.addr(200 + i);
            staking.addTarget(validators[i]);
            if (i != 1) {
                DkgContract.Registration memory record = registration(validators[i], 10);
                VM.prank(validators[i]);
                dkg.register(EPOCH, record);
            }
        }
        staking.setEpoch(6, true);

        VM.prank(validators[0]);
        dkg.postPcQc(EPOCH, pcQc(1, 0x11, 1));

        VM.prank(validators[0]);
        dkg.postPcQc(EPOCH, pcQc(3, 0x12, 1));
        VM.expectRevert();
        VM.prank(validators[0]);
        dkg.postPcQc(EPOCH, pcQc(4, 0x13, 1));
        require(dkg.records(EPOCH, 0, 10).total == 2, "wrong compact party count");
    }

    function testNonTargetValidatorCannotPostProtocolRecord() external {
        Fixture memory fixture = deploySession();
        address outsider = VM.addr(999);
        fixture.staking.addValidator(outsider);
        VM.expectRevert();
        VM.prank(outsider);
        fixture.dkg.postPcQc(EPOCH, pcQc(2, 0x11, 1));
    }

    function testPartySetCanExceedLegacyBitmapWidth() external {
        TestValidatorLookup staking = new TestValidatorLookup();
        DkgContract dkg = new DkgContract(address(staking));
        address first;
        for (uint256 i = 0; i < 257; i++) {
            address validator = address(uint160(1000 - i));
            if (i == 0) {
                first = validator;
            }
            staking.addTarget(validator);
            DkgContract.Registration memory record = registration(validator, 10);
            VM.prank(validator);
            dkg.register(EPOCH, record);
        }
        staking.setEpoch(6, true);

        VM.prank(first);
        dkg.postPcQc(EPOCH, pcQc(256, 0x11, 1));
        require(dkg.records(EPOCH, 0, 1).total == 1, "large party set was rejected");
    }

    function testPcAndBveRecordsAreStoredAsTypedRecords() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory pc = pcQc(2, 0x11, 1);
        DkgContract.BveQc memory bve = bveQc(3, 0x22, 1);

        postPc(fixture, pc);
        postBve(fixture, 0, bve);

        DkgContract.RecordPage memory first = fixture.dkg.records(EPOCH, 0, 1);
        require(first.total == 2 && first.next == 1, "wrong first page boundary");
        require(first.pcQcs.length == 1 && first.pcQcs[0].sequence == 0, "wrong PC page");
        DkgContract.PcQc memory storedPc = first.pcQcs[0].qc;
        require(storedPc.dealer == pc.dealer && storedPc.digest == pc.digest, "wrong PC");
        require(storedPc.signatures.length == 1, "wrong PC witness");

        DkgContract.RecordPage memory second = fixture.dkg.records(EPOCH, first.next, 1);
        require(second.total == 2 && second.next == 2, "wrong second page boundary");
        require(second.bveQcs.length == 1 && second.bveQcs[0].sequence == 1, "wrong BVE page");
        DkgContract.BveQc memory storedBve = second.bveQcs[0].qc;
        require(
            storedBve.dealer == bve.dealer && storedBve.digest == bve.digest
                && storedBve.commitmentDigest == bve.commitmentDigest,
            "wrong BVE"
        );
    }

    function testEmptyRecordPageCarriesItsTotal() external {
        (DkgContract dkg,,) = deploySingleRegistrationTarget();
        DkgContract.RecordPage memory page = dkg.records(EPOCH, 0, 1);
        require(page.total == 0 && page.next == 0, "wrong empty page boundary");
        require(page.pcQcs.length == 0 && page.bveQcs.length == 0 && page.results.length == 0, "nonempty page");
    }

    function testProtocolRecordsEmitTypedEvents() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory pc = pcQc(2, 0x11, 1);
        DkgContract.BveQc memory bve = bveQc(3, 0x22, 1);

        VM.expectEmit(true, true, true, true, address(fixture.dkg));
        emit PcQcPosted(EPOCH, 0, pc.dealer, pc.digest, pc.signatures);
        postPc(fixture, pc);

        VM.expectEmit(true, true, true, true, address(fixture.dkg));
        emit BveQcPosted(EPOCH, 1, bve.dealer, bve.digest, bve.commitmentDigest, bve.signatures);
        postBve(fixture, 0, bve);

        DkgContract.DkgResult memory result = signedResult(fixture, 0x33);
        VM.expectEmit(true, true, false, true, address(fixture.dkg));
        emit DkgResultPosted(EPOCH, 2, result.sessionId, result.g2x, result.signatures);
        submitResult(fixture, result);
    }

    function testPcQcIsBoundedPerSubmittingValidatorAndDealer() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory original = pcQc(3, 0x11, 1);

        postPc(fixture, original);
        postPc(fixture, original);
        require(recordTotal(fixture.dkg) == 1, "identical QC was recorded twice");

        DkgContract.PcQc memory alternateWitness = pcQc(3, 0x11, 2);
        postPc(fixture, alternateWitness);
        require(recordTotal(fixture.dkg) == 1, "submitter posted two witnesses for one dealer");

        postPcAs(fixture, 1, alternateWitness);
        require(recordTotal(fixture.dkg) == 2, "second validator could not post its witness");
    }

    function testBveQcIsBoundedPerSubmittingValidatorAndDealer() external {
        Fixture memory fixture = deploySession();

        postBve(fixture, 0, bveQc(3, 0x11, 1));
        postBve(fixture, 0, bveQc(3, 0x11, 2));
        require(recordTotal(fixture.dkg) == 1, "submitter posted two witnesses for one dealer");

        postBve(fixture, 1, bveQc(3, 0x11, 3));
        require(recordTotal(fixture.dkg) == 2, "second validator could not post its witness");
    }

    function testMalformedQcCannotOccupyRecordSlot() external {
        Fixture memory fixture = deploySession();
        DkgContract.PcQc memory malformed = pcQc(1, 0x11, 1);
        malformed.signatures[0].signer = 4;

        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.postPcQc(EPOCH, malformed);

        malformed = pcQc(4, 0x11, 1);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.postPcQc(EPOCH, malformed);
    }

    function testSubmitResultVerifiesQuorumSignatures() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        submitResult(fixture, result);

        DkgContract.RecordPage memory page = fixture.dkg.records(EPOCH, 0, 1);
        require(page.total == 1 && page.next == 1, "wrong result page boundary");
        require(page.results.length == 1 && page.results[0].sequence == 0, "wrong result page");
        require(page.results[0].result.sessionId == result.sessionId, "wrong session id");
        require(page.results[0].result.g2x[0] == result.g2x[0], "wrong result point");

        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
    }

    function testSubmitResultUsesConsensusStakeDuringTargetEpoch() external {
        Fixture memory fixture = deploySession();
        // The party set was already persisted, so this proves DONE reads stake
        // at verification instead of persisting it with the party IDs.
        postPc(fixture, pcQc(0, 0x11, 1));
        fixture.staking.setConsensusStake(fixture.validators[0], 7 ether);
        fixture.staking.setEpoch(EPOCH, false);
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        DkgContract.QcSignature[] memory highStakeQuorum = new DkgContract.QcSignature[](1);
        highStakeQuorum[0] = result.signatures[0];
        result.signatures = highStakeQuorum;
        submitResult(fixture, result);
    }

    function testSubmitResultUsesSnapshotStakeAfterTargetBoundary() external {
        Fixture memory fixture = deploySession();
        postPc(fixture, pcQc(0, 0x11, 1));
        fixture.staking.setSnapshotStake(fixture.validators[0], 7 ether);
        fixture.staking.setEpoch(EPOCH, true);

        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        DkgContract.QcSignature[] memory highStakeQuorum = new DkgContract.QcSignature[](1);
        highStakeQuorum[0] = result.signatures[0];
        result.signatures = highStakeQuorum;
        submitResult(fixture, result);
    }

    function testSubmitResultRejectsAfterStakeWindowExpires() external {
        Fixture memory fixture = deploySession();
        postPc(fixture, pcQc(0, 0x11, 1));
        fixture.staking.setEpoch(EPOCH + 1, false);
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);

        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
    }

    function testSubmitResultRoundsStakeToNearestMon() external {
        Fixture memory fixture = deploySession();
        fixture.staking.setStake(fixture.validators[0], 6 ether + 0.5 ether);
        for (uint256 i = 1; i < fixture.validators.length; i++) {
            fixture.staking.setStake(fixture.validators[i], 1 ether + 0.49 ether);
        }
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        DkgContract.QcSignature[] memory roundedQuorum = new DkgContract.QcSignature[](1);
        roundedQuorum[0] = result.signatures[0];
        result.signatures = roundedQuorum;
        submitResult(fixture, result);
    }

    function testSinglePartySetCanPost() external {
        (DkgContract dkg, TestValidatorLookup staking, address validator) = deploySingleRegistrationTarget();
        uint256 qcKey = 1;
        DkgContract.Registration memory record = registration(validator, qcKey);
        VM.prank(validator);
        dkg.register(EPOCH, record);
        staking.setEpoch(6, true);
        VM.prank(validator);
        dkg.postPcQc(EPOCH, pcQc(0, 0x11, 1));
        require(dkg.records(EPOCH, 0, 1).total == 1, "singleton party set was rejected");
    }

    function testSubmitResultRejectsTamperedPointAndSignature() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        result.sessionId = bytes32(uint256(result.sessionId) ^ 1);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);

        result = signedResult(fixture, 0x44);
        result.g2x[5] = bytes32(uint256(result.g2x[5]) + 1);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);

        result = signedResult(fixture, 0x44);
        result.signatures[1].s = bytes32(uint256(result.signatures[1].s) ^ 1);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
    }

    function testDoneQcRequiresCanonicalSignerOrder() external {
        Fixture memory fixture = deploySession();
        DkgContract.DkgResult memory result = signedResult(fixture, 0x44);
        (result.signatures[0], result.signatures[2]) = (result.signatures[2], result.signatures[0]);
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);

        result = signedResult(fixture, 0x44);
        result.signatures[2] = result.signatures[1];
        VM.expectRevert();
        VM.prank(fixture.validators[0]);
        fixture.dkg.submitResult(EPOCH, result);
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
    }

    function deploySession() private returns (Fixture memory fixture) {
        fixture.staking = new TestValidatorLookup();
        fixture.dkg = new DkgContract(address(fixture.staking));
        for (uint256 i = 0; i < 4; i++) {
            fixture.validators[i] = VM.addr(100 + i);
            fixture.qcKeys[i] = i == 3 ? 6 : i + 1;
            fixture.staking.addTarget(fixture.validators[i]);
            DkgContract.Registration memory record = registration(fixture.validators[i], fixture.qcKeys[i]);
            VM.prank(fixture.validators[i]);
            fixture.dkg.register(EPOCH, record);
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
        postPcAs(fixture, 0, qc);
    }

    function postPcAs(Fixture memory fixture, uint256 validatorIndex, DkgContract.PcQc memory qc) private {
        VM.prank(fixture.validators[validatorIndex]);
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

    function recordTotal(DkgContract dkg) private view returns (uint64) {
        return dkg.records(EPOCH, 0, 1).total;
    }

    function registration(address party, uint256 qcKey) private pure returns (DkgContract.Registration memory result) {
        result.qcVerifier = VM.addr(qcKey);
        uint256 receiverKey = 1001;
        result.receiverPublicKey =
            DkgContract.SecpPoint({prefix: 3, x: 0x9d1abaec9f5715a15c7628244170951e0f85e87f68ca5393d3f9fc3fa23a69c8});
        bytes32 digest =
            receiverKeyProofDigest(party, result.qcVerifier, result.receiverPublicKey, result.receiverProofNonce);
        (, result.receiverProofR, result.receiverProofS) = VM.sign(receiverKey, digest);
    }

    function receiverKeyProofDigest(
        address party,
        address qcVerifier,
        DkgContract.SecpPoint memory receiverKey,
        uint32 proofNonce
    ) private pure returns (bytes32) {
        return sha256(
            abi.encodePacked(
                "BTX-DKG/protocol/receiver-key-pop/v1",
                party,
                _le64(EPOCH),
                qcVerifier,
                receiverKey.prefix,
                receiverKey.x,
                _le32(proofNonce)
            )
        );
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
        for (uint256 i = 0; i < 6; i++) {
            result.g2x[i] = bytes32(uint256(pointByte) + i);
        }
        result.sessionId = deriveSessionId(EPOCH, fixture.validators, fixture.qcKeys);
        bytes32 digest = doneQcDigest(EPOCH, result.sessionId, result.g2x);
        result.signatures = new DkgContract.QcSignature[](3);
        for (uint32 i = 0; i < 3; i++) {
            (, bytes32 r, bytes32 s) = VM.sign(fixture.qcKeys[i], digest);
            result.signatures[i] = DkgContract.QcSignature({signer: i, r: r, s: s});
        }
    }

    function deriveSessionId(uint64 epoch, address[4] memory parties, uint256[4] memory keys)
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
            session = bytes.concat(session, bytes20(VM.addr(keys[i])));
        }
        session = bytes.concat(session, _le64(4));
        for (uint256 i = 0; i < 4; i++) {
            session = bytes.concat(session, bytes20(parties[i]));
        }
        return sha256(session);
    }

    function doneQcDigest(uint64 epoch, bytes32 sessionId, bytes32[6] memory g2x) private pure returns (bytes32) {
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
