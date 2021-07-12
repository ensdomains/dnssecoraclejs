import * as packet from 'dns-packet'
import * as types from 'dns-packet/types';
import { utils } from 'ethers';
import { Provider } from "@ethersproject/providers";
import { DNSSEC } from './typechain/DNSSEC';
import { DNSSEC__factory } from './typechain/factories/DNSSEC__factory';
import { ProvableAnswer, SignedSet } from '@ensdomains/dnsprovejs';
import { logger } from './log'

export class OutdatedDataError extends Error {
    answer: SignedSet<any>;

    constructor(answer: SignedSet<any>) {
        super(`Oracle has a newer version of the ${answer.signature.data.typeCovered} RRSET on ${answer.signature.name}`);
        this.name = 'OudatedDataError';
        this.answer = answer;
    }
}

// Compares two serial numbers using RFC1982 serial number math.
function serialNumberGt(i1: number, i2: number): boolean {
    return (i1 < i2 && i2 - i1 > 0x7fffffff) || (i1 > i2 && i1 - i2 < 0x7fffffff);
}

export interface RRSetWithSignature {
    rrset: Buffer;
    sig: Buffer;
}

export class Oracle {
    contract: DNSSEC;
    now: () => number;

    constructor(address: string, provider: Provider, now: (() => number | undefined) = undefined) {
        this.contract = DNSSEC__factory.connect(address, provider);
        this.now = now || Date.now;
    }

    // Takes a `ProvableAnswer` returned by dnsprovejs and converts it into a blob of proof
    // data for the DNSSEC oracle contract.
    async getProofData(answer: ProvableAnswer<any>): Promise<{rrsets: RRSetWithSignature[], proof: Buffer}> {
        const allProofs = answer.proofs.concat([answer.answer]);
        for(let i = allProofs.length - 1; i >= 0; i--) {
            if(await this.knownProof(allProofs[i])) {
                if(i == allProofs.length - 1) {
                    logger.info(`All proofs for ${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} are already known`);
                    return {rrsets: [], proof: allProofs[allProofs.length - 1].toWire(false)};
                }
                logger.info(`${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} has ${i + 1} of ${allProofs.length} proofs already known`);
                return {
                    rrsets: this.encodeProofs(allProofs.slice(i + 1, allProofs.length)),
                    proof: allProofs[i].toWire(false),
                };
            }
        }
        logger.info(`${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} has no proofs already known`);
        return {
            rrsets: this.encodeProofs(allProofs),
            proof: Buffer.from(utils.arrayify(await this.contract.anchors())),
        };
    }

    private async knownProof(proof: SignedSet<any>): Promise<boolean> {
        const name = packet.name.encode(proof.signature.name);
        const type = types.toType(proof.signature.data.typeCovered);
        const [inception, expiration, hash] = await this.contract.rrdata(type, name);
        // If the existing record is newer than our one, throw an error.
        if(serialNumberGt(inception, proof.signature.data.inception)) {
            throw new OutdatedDataError(proof);
        }
        const expired = serialNumberGt(this.now() / 1000, expiration);
        const proofHash = utils.keccak256(proof.toWire(false)).slice(0, 42);
        return (hash == proofHash) && !expired;
    }

    private encodeProofs(proofs: SignedSet<any>[]): RRSetWithSignature[] {
        return proofs.map((proof) => ({rrset: proof.toWire(true), sig: proof.signature.data.signature}));
    }
}