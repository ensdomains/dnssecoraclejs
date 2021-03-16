/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import { Signer } from "ethers";
import { Provider, TransactionRequest } from "@ethersproject/providers";
import { Contract, ContractFactory, Overrides } from "@ethersproject/contracts";

import type { RSASHA256Algorithm } from "../RSASHA256Algorithm";

export class RSASHA256Algorithm__factory extends ContractFactory {
  constructor(signer?: Signer) {
    super(_abi, _bytecode, signer);
  }

  deploy(overrides?: Overrides): Promise<RSASHA256Algorithm> {
    return super.deploy(overrides || {}) as Promise<RSASHA256Algorithm>;
  }
  getDeployTransaction(overrides?: Overrides): TransactionRequest {
    return super.getDeployTransaction(overrides || {});
  }
  attach(address: string): RSASHA256Algorithm {
    return super.attach(address) as RSASHA256Algorithm;
  }
  connect(signer: Signer): RSASHA256Algorithm__factory {
    return super.connect(signer) as RSASHA256Algorithm__factory;
  }
  static connect(
    address: string,
    signerOrProvider: Signer | Provider
  ): RSASHA256Algorithm {
    return new Contract(address, _abi, signerOrProvider) as RSASHA256Algorithm;
  }
}

const _abi = [
  {
    inputs: [
      {
        internalType: "bytes",
        name: "key",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "data",
        type: "bytes",
      },
      {
        internalType: "bytes",
        name: "sig",
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
    stateMutability: "view",
    type: "function",
  },
];

const _bytecode =
  "0x608060405234801561001057600080fd5b50610983806100206000396000f3fe608060405234801561001057600080fd5b506004361061002b5760003560e01c8063de8f50a114610030575b600080fd5b6101516004803603606081101561004657600080fd5b810190808035906020019064010000000081111561006357600080fd5b82018360208201111561007557600080fd5b8035906020019184600183028401116401000000008311171561009757600080fd5b9091929391929390803590602001906401000000008111156100b857600080fd5b8201836020820111156100ca57600080fd5b803590602001918460018302840111640100000000831117156100ec57600080fd5b90919293919293908035906020019064010000000081111561010d57600080fd5b82018360208201111561011f57600080fd5b8035906020019184600183028401116401000000008311171561014157600080fd5b9091929391929390505050610169565b60405180821515815260200191505060405180910390f35b600060608060006101c860048b8b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050506104be90919063ffffffff16565b60ff16905060008161ffff16146102ac5761023760058261ffff168c8c8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050506104e29092919063ffffffff16565b92506102a56005820161ffff1660058361ffff168d8d905003038c8c8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050506104e29092919063ffffffff16565b91506103d5565b61030460058b8b8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f8201169050808301925050505050505061056c90919063ffffffff16565b905061036460078261ffff168c8c8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050506104e29092919063ffffffff16565b92506103d26007820161ffff1660078361ffff168d8d905003038c8c8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f820116905080830192505050505050506104e29092919063ffffffff16565b91505b6000606061042884868a8a8080601f016020809104026020016040519081016040528093929190818152602001838380828437600081840152601f19601f82011690508083019250505050505050610592565b80925081935050508180156104ad575061044f6020825103826105ad90919063ffffffff16565b60028b8b604051808383808284378083019250505092505050602060405180830381855afa158015610485573d6000803e3d6000fd5b5050506040513d602081101561049a57600080fd5b8101908080519060200190929190505050145b955050505050509695505050505050565b60008282815181106104cc57fe5b602001015160f81c60f81b60f81c905092915050565b6060835182840111156104f457600080fd5b60608267ffffffffffffffff8111801561050d57600080fd5b506040519080825280601f01601f1916602001820160405280156105405781602001600182028036833780820191505090505b509050600080602083019150856020880101905061055f8282876105cf565b8293505050509392505050565b6000825160028301111561057f57600080fd5b61ffff8260028501015116905092915050565b600060606105a1838587610618565b91509150935093915050565b600082516020830111156105c057600080fd5b81602084010151905092915050565b5b602081106105f357815183526020830192506020820191506020810390506105d0565b60006001826020036101000a0390508019835116818551168181178652505050505050565b60006060600083518551875160600101019050610633610933565b610646828261073590919063ffffffff16565b5061065e875160001b8261078990919063ffffffff16565b50610676865160001b8261078990919063ffffffff16565b5061068e855160001b8261078990919063ffffffff16565b506106a287826107ab90919063ffffffff16565b506106b686826107ab90919063ffffffff16565b506106ca85826107ab90919063ffffffff16565b50845167ffffffffffffffff811180156106e357600080fd5b506040519080825280601f01601f1916602001820160405280156107165781602001600182028036833780820191505090505b50925084516020840183602084510160055afa93505050935093915050565b61073d610933565b60006020838161074957fe5b0614610762576020828161075957fe5b06602003820191505b81836020018181525050604051808452600081528281016020016040525082905092915050565b610791610933565b6107a3838460000151518460206107cd565b905092915050565b6107b3610933565b6107c58384600001515184855161083a565b905092915050565b6107d5610933565b846020015184830111156107f3576107f2856002868501026108f3565b5b60006001836101000a0390508260200360080284901c9350855183868201018583198251161781528151858801111561082c5784870182525b505085915050949350505050565b610842610933565b825182111561085057600080fd5b8460200151828501111561087b5761087a8560026108748860200151888701610917565b026108f3565b5b60008086518051876020830101935080888701111561089a5787860182525b60208701925050505b602084106108c657805182526020820191506020810190506020840393506108a3565b60006001856020036101000a03905080198251168184511681811785525050879350505050949350505050565b6060826000015190506109068383610735565b5061091183826107ab565b50505050565b6000818311156109295782905061092d565b8190505b92915050565b60405180604001604052806060815260200160008152509056fea26469706673582212207bb17b5accc61466fa58dc5efb0d5d64904e78d4ab783428d54a3859e087d59464736f6c63430007040033";