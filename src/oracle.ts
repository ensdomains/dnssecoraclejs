import * as packet from 'dns-packet'
import * as types from 'dns-packet/types';
import { utils } from 'ethers';
import { Provider } from "@ethersproject/providers";
import { DNSSEC } from '../typechain/DNSSEC';
import { DNSSEC__factory } from '../typechain/factories/DNSSEC__factory';
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

enum Status {
    None = 0,
    Some = 1,
    All = 2
}

export class Oracle {
    contract: DNSSEC;
    now: () => number;

    constructor(address: string, provider: Provider, now: (() => number | undefined) = undefined) {
        this.contract = DNSSEC__factory.connect(address, provider);
        this.now = now || Date.now;
    }

    decodeProofs(data: Buffer): SignedSet<any>[] {
        const proofs = [];
        for(let off = 0; off < data.length;) {
            const datalen = data.readInt16BE(off);
            const rrdata = data.slice(off + 2, off + 2 + datalen);
            off += datalen + 2;
            const siglen = data.readInt16BE(off);
            const sigdata = data.slice(off + 2, off + 2 + siglen);
            off += siglen + 2;
            proofs.push(SignedSet.fromWire(rrdata, sigdata));
        }
        return proofs;
    }
    
    decodeRrset(data: Buffer): packet.Answer[] {
        const rrs = [];
        let off = 0;
        while(off < data.length) {
            rrs.push(packet.answer.decode(data, off));
            off += packet.answer.decode.bytes;
        }
        return rrs;
    }

    // Takes a `ProvableAnswer` returned by dnsprovejs and converts it into a blob of proof
    // data for the DNSSEC oracle contract.
    async getProofData(answer: ProvableAnswer<any>): Promise<{data: Buffer, status:Status, proof: Buffer}> {
        const allProofs = answer.proofs.concat([answer.answer]);
        for(let i = allProofs.length - 1; i >= 0; i--) {
            if(await this.knownProof(allProofs[i])) {
                if(i == allProofs.length - 1) {
                    console.log(`All proofs for ${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} are already known`);
                    return {data: Buffer.of(), status:2, proof: Buffer.of()};
                }
                logger.info(`${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} has ${i + 1} of ${allProofs.length} proofs already known`);
                return {
                    data: this.encodeProofs(allProofs.slice(i + 1, allProofs.length)),
                    status:1,
                    proof: allProofs[i].toWire(false),
                };
            }
        }
        logger.info(`${answer.answer.signature.data.typeCovered} ${answer.answer.signature.name} has no proofs already known`);
        return {
            data: this.encodeProofs(allProofs),
            status: 0,
            proof: Buffer.from(utils.arrayify(await this.contract.anchors())),
        };
    }

    private async knownProof(proof: SignedSet<any>): Promise<boolean> {
        const name = packet.name.encode(proof.signature.name);
        const type = types.toType(proof.signature.data.typeCovered);
        const [inception, inserted, hash] = await this.contract.rrdata(type, name);
        if(inception > proof.signature.data.inception) {
            throw new OutdatedDataError(proof);
        }
        const expired = inserted.toNumber() + proof.signature.data.originalTTL < this.now() / 1000;
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