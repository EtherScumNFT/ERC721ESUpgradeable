// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts-upgradeable@5.0.0/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/ERC721Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/access/extensions/AccessControlEnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/access/OwnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/common/ERC2981Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721BurnableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721ConsecutiveUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721EnumerableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721RoyaltyUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721URIStorageUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/token/ERC721/extensions/ERC721WrapperUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/cryptography/EIP712Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/introspection/ERC165Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/ContextUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/MulticallUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/NoncesUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/utils/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable@5.0.0/proxy/utils/UUPSUpgradeable.sol";

/// @custom:security-contact bedlam520@skiff.com
contract SCUMWalkers is Initializable, UUPSUpgradeable, ERC721Upgradeable, AccessControlEnumerableUpgradeable, OwnableUpgradeable, ERC2981Upgradeable, ERC721BurnableUpgradeable, ERC721ConsecutiveUpgradeable, ERC721EnumerableUpgradeable, ERC721PausableUpgradeable, ERC721URIStorageUpgradeable, EIP712Upgradeable {
    uint256 private _nextTokenId;

    string private _baseTokenURI;

    function setBaseURI(string memory baseURI) external onlyOwner {
        _baseTokenURI = baseURI;
    }
   
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialowner) initializer public {
        __ERC721_init("SCUMWalkers", "SW");
        __ERC721Enumerable_init();
        __ERC721URIStorage_init();
        __ERC721Pausable_init();
        __Ownable_init(initialowner);
        __UUPSUpgradeable_init();
        __EIP712_init("SCUMWalkers", "1");
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

function _authorizeUpgrade(address _newImplementation) internal override onlyOwner {}


    function safeMint(address to, string memory uri) public onlyOwner {
        uint256 tokenId = _nextTokenId++;
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
    }

    function _ownerOf(uint256 tokenId) internal view override(ERC721Upgradeable, ERC721ConsecutiveUpgradeable) returns (address) {
    // Add your implementation logic here
    return ERC721Upgradeable._ownerOf(tokenId);
}

    // The following functions are overrides required by Solidity.

    function _update(address to, uint256 tokenId, address auth)
        internal
        override(ERC721ConsecutiveUpgradeable, ERC721EnumerableUpgradeable, ERC721PausableUpgradeable, ERC721Upgradeable)
        returns (address)
    {
        return super._update(to, tokenId, auth);
    }

    function _increaseBalance(address account, uint128 value)
        internal
        override(ERC721Upgradeable, ERC721EnumerableUpgradeable)
    {
        super._increaseBalance(account, value);
    }

    function _BaseURI() public view returns (string memory) {
        return _baseTokenURI;
    }
    
    function tokenURI(uint256 tokenId)
        public
        view
        override(ERC721Upgradeable, ERC721URIStorageUpgradeable)
        returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControlEnumerableUpgradeable, ERC2981Upgradeable, ERC721Upgradeable, ERC721EnumerableUpgradeable, ERC721URIStorageUpgradeable)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
