/* Autogenerated file. Do not edit manually. */
/* tslint:disable */
/* eslint-disable */

import {
  ethers,
  EventFilter,
  Signer,
  BigNumber,
  BigNumberish,
  PopulatedTransaction,
} from "ethers";
import {
  Contract,
  ContractTransaction,
  CallOverrides,
} from "@ethersproject/contracts";
import { BytesLike } from "@ethersproject/bytes";
import { Listener, Provider } from "@ethersproject/providers";
import { FunctionFragment, EventFragment, Result } from "@ethersproject/abi";

interface SHA1DigestInterface extends ethers.utils.Interface {
  functions: {
    "verify(bytes,bytes)": FunctionFragment;
  };

  encodeFunctionData(
    functionFragment: "verify",
    values: [BytesLike, BytesLike]
  ): string;

  decodeFunctionResult(functionFragment: "verify", data: BytesLike): Result;

  events: {};
}

export class SHA1Digest extends Contract {
  connect(signerOrProvider: Signer | Provider | string): this;
  attach(addressOrName: string): this;
  deployed(): Promise<this>;

  on(event: EventFilter | string, listener: Listener): this;
  once(event: EventFilter | string, listener: Listener): this;
  addListener(eventName: EventFilter | string, listener: Listener): this;
  removeAllListeners(eventName: EventFilter | string): this;
  removeListener(eventName: any, listener: Listener): this;

  interface: SHA1DigestInterface;

  functions: {
    verify(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<[boolean]>;

    "verify(bytes,bytes)"(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<[boolean]>;
  };

  verify(
    data: BytesLike,
    hash: BytesLike,
    overrides?: CallOverrides
  ): Promise<boolean>;

  "verify(bytes,bytes)"(
    data: BytesLike,
    hash: BytesLike,
    overrides?: CallOverrides
  ): Promise<boolean>;

  callStatic: {
    verify(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>;

    "verify(bytes,bytes)"(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<boolean>;
  };

  filters: {};

  estimateGas: {
    verify(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<BigNumber>;

    "verify(bytes,bytes)"(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<BigNumber>;
  };

  populateTransaction: {
    verify(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;

    "verify(bytes,bytes)"(
      data: BytesLike,
      hash: BytesLike,
      overrides?: CallOverrides
    ): Promise<PopulatedTransaction>;
  };
}
