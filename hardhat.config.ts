import "@typechain/hardhat";

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: "0.8.4",
  networks: {
    hardhat: {
      initialDate: "2021-06-29T00:00:00Z"
    }
  },
  typechain: {
    outDir: "src/typechain",
  }
};
