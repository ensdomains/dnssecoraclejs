import "@nomiclabs/hardhat-waffle";
import "hardhat-typechain";

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: "0.7.4",
  networks: {
    hardhat: {
      initialDate: "2021-02-10T00:00:00Z"
    }
  }
};
