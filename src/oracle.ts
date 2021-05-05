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
function serialNumberGte(i1: number, i2: number): boolean {
    return (i1 < i2 && i2 - i1 > 2147483648) || (i1 > i2 && i1 - i2 < 2147483648);
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
    async getProofData(answer: ProvableAnswer<any>): Promise<{data: Buffer, proof: Buffer}> {
        const allProofs = answer.proofs.concat([answer.answer]);
        for(let i = allProofs.length - 1; i >= 0; i--) {
            if(await this.knownProof(allProofs[i])) {
                if(i == allProofs.length - 1) {
                    console.log(`All proofs for ${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} are already known`);
                    return {data: Buffer.of(), proof: allProofs[allProofs.length - 1].toWire(false)};
                }
                logger.info(`${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} has ${i + 1} of ${allProofs.length} proofs already known`);
                return {
                    data: this.encodeProofs(allProofs.slice(i + 1, allProofs.length)),
                    proof: allProofs[i].toWire(false),
                };
            }
        }
        logger.info(`${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} has no proofs already known`);
        return {
            data: this.encodeProofs(allProofs),
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
        const expired = serialNumberGt(this.now() / 1000, expiration + proof.signature.data.originalTTL);
        const proofHash = utils.keccak256(proof.toWire(false)).slice(0, 42);
        return (hash == proofHash) && !expired;
    }

    private encodeProofs(proofs: SignedSet<any>[]): Buffer {
        const buffers = new Array<Buffer>(proofs.length);
        for(let i = 0; i < proofs.length; i++) {
            const proof = proofs[i];
            const data = proof.toWire(true);
            const sig = proof.signature.data.signature;
            const buf = Buffer.alloc(data.length + sig.length + 4);
            buf.writeInt16BE(data.length, 0);
            data.copy(buf, 2);
            buf.writeInt16BE(sig.length, data.length + 2);
            sig.copy(buf, data.length + 4);
            buffers[i] = buf;
        }
        return Buffer.concat(buffers);
    }
}