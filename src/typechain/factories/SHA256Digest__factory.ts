/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import { Contract, ContractFactory, Overrides } from "@ethersproject/contracts";

import type { SHA256Digest } from "../SHA256Digest";

export class SHA256Digest__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(overrides?: Overrides): Promise<SHA256Digest> {
    return super.deploy(overrides || {}) as Promise<SHA256Digest>;
  }
  getDeployTransaction(overrides?: Overrides): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): SHA256Digest {
    return super.attach(address) as SHA256Digest;
  }
  connect(signer: Signer): SHA256Digest__factory {
    return super.connect(signer) as SHA256Digest__factory;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): SHA256Digest {
    return new Contract(address, _abi, signerOrProvider) as SHA256Digest;
  }
}

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "hash",
        type: "bytes",
      },
    ],
    name: "verify",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "pure",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b5061022d806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063f7e83aee14610030575b600080fd5b6100fc6004803603604081101561004657600080fd5b810190808035906020019064010000000081111561006357600080fd5b82018360208201111561007557600080fd5b8035906020019184600183028401116401000000008311171561009757600080fd5b9091929391929390803590602001906401000000008111156100b857600080fd5b8201836020820111156100ca57600080fd5b803590602001918460018302840111640100000000831117156100ec57600080fd5b9091929391929390505050610114565b60405180821515815260200191505060405180910390f35b600061016e600084848080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050506101d590919063ffffffff16565b60028686604051808383808284378083019250505092505050602060405180830381855afa1580156101a4573d6000803e3d6000fd5b5050506040513d60208110156101b957600080fd5b8101908080519060200190929190505050149050949350505050565b600082516020830111156101e857600080fd5b8160208401015190509291505056fea2646970667358221220c59d2b206a5ca6ba28cf4d5e8bd59c04355c9d65e68e4a36718a86c00abd0daf64736f6c63430007040033";
