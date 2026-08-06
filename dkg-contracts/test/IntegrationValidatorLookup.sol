// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @dev Minimal staking-precompile substitute used by the DKG integration test.
contract IntegrationValidatorLookup {
    uint256 private constant VALIDATOR_STAKE = 1 ether;
    uint32 private constant PAGE_SIZE = 100;

    uint64 private immutable EPOCH_LENGTH;
    mapping(address validator => uint64 validatorId) private validatorIds;
    uint64[] private validators;

    constructor(uint64 epochLength_) {
        require(epochLength_ != 0);
        EPOCH_LENGTH = epochLength_;
    }

    function addTarget(address validator) external {
        require(validator != address(0) && validatorIds[validator] == 0);
        uint64 validatorId = uint64(validators.length + 1);
        validatorIds[validator] = validatorId;
        validators.push(validatorId);
    }

    function getValidatorId(address validator) external view returns (uint64) {
        return validatorIds[validator];
    }

    function getEpoch() external view returns (uint64 epoch, bool inEpochDelayPeriod) {
        return (uint64(block.number / EPOCH_LENGTH) + 1, false);
    }

    function getConsensusValidatorSet(uint32 startIndex)
        external
        view
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds_)
    {
        return _validatorSet(startIndex);
    }

    function getSnapshotValidatorSet(uint32 startIndex)
        external
        view
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds_)
    {
        return _validatorSet(startIndex);
    }

    /// @dev The real precompile returns ten fixed words before dynamic key data.
    /// Returning those words here keeps consensus and snapshot stake at offsets
    /// consumed by DkgContract and gives the integration runner whole-MON input.
    function getValidator(uint64 validatorId)
        external
        view
        returns (
            uint256 word0,
            uint256 word1,
            uint256 word2,
            uint256 word3,
            uint256 word4,
            uint256 word5,
            uint256 consensusStake,
            uint256 word7,
            uint256 snapshotStake,
            uint256 word9
        )
    {
        require(validatorId != 0 && validatorId <= validators.length);
        return (0, 0, 0, 0, 0, 0, VALIDATOR_STAKE, 0, VALIDATOR_STAKE, 0);
    }

    function _validatorSet(uint32 startIndex)
        private
        view
        returns (bool done, uint32 nextIndex, uint64[] memory validatorIds_)
    {
        if (startIndex >= validators.length) {
            return (true, startIndex, new uint64[](0));
        }
        uint256 requestedEnd = uint256(startIndex) + PAGE_SIZE;
        uint256 end = requestedEnd < validators.length ? requestedEnd : validators.length;
        validatorIds_ = new uint64[](end - startIndex);
        for (uint256 i = startIndex; i < end; i++) {
            validatorIds_[i - startIndex] = validators[i];
        }
        // The integration validator set is tiny; the uint32 page cursor cannot truncate.
        // forge-lint: disable-next-line(unsafe-typecast)
        return (end == validators.length, uint32(end), validatorIds_);
    }
}
