import * as packet from 'dns-packet';
import * as chai from 'chai';
import { expect } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import { ethers } from 'hardhat';
import { Contract } from 'ethers';
import { DNSProver, SignedSet, DEFAULT_TRUST_ANCHORS } from '@ensdomains/dnsprovejs';

import { Oracle } from '../src/oracle';

const MATOKEN_1 = {
    '_ens.matoken.live': {
        TXT: '000181a00001000200000001045f656e73076d61746f6b656e046c6976650000100001045f656e73076d61746f6b656e046c697665000010000100000129002d2c613d307861353331333036306639666136623630376163386361383732386138353131363663396636313237045f656e73076d61746f6b656e046c69766500002e00010000012900a0001008030000012c603a54c7601d53c7de18076d61746f6b656e046c697665002d2de2c7102099709c8f27fd86dcd07d3151aa00fa42a9bb9bb63d87e045c820f7c2a2d9777798c87e2b138f9a3cda291045ef924cbec1c5a3674cfa2c7c05ebdf3b21db9a2e6315fe61ddaf13ea3d88740375baf59c72b15a57513502c213c590b27346b8307990df7577631b12e97d83c0118ce358d636707c0bee2589a99d00002904d0000080000000'
    },
    'matoken.live': {
        DNSKEY: '000181a00001000300000001076d61746f6b656e046c6976650000300001076d61746f6b656e046c69766500003000010000012c00880100030803010001a5f9cc31988361c8878e267b6d940602b5a7bc32652851e54112f1f3b28b92501de4f33b9f8c3b25ca200020a99a7a8a5505cbdb4601a65bf0848921033871f878bd41ef4c00b4a11a3d584f9ed50aaef45c9993db98d61d1faeaca82d757b6bbdeafeeb3b74142cde78bda7627fa33e51da1e4b6bfca9425219b9a0951a7113076d61746f6b656e046c69766500003000010000012c010801010308030100019afbf926c29ca823425693bbcb023c15f0bfe8abb0e8ed8e77d69500790a5ffb54a807c45a2df69079f39774f0e14168d23442eacf9e8f665ab359820d216a6c587ad9a7e1688566b11e425166610e870b177741bf04650fe02a5a73c70e4234f38b46c6f740d68a5fbd83bb6a3eb978ad8b572def024628d85bed88b96a6894371d8842419ef952ef5a485d90fbbe17ab5b5fc4bc8e36fc3a42c9d3792892d60944fbb1deeb050fdbe854bd55c7b3c8e7d35fb4c6b1d6742480ed1b5cc9343e8a6fec0d35ead4010b7bc0ae66686caf451d680cf48c027ab2658c750451996a9d7ee30917a9293e267a7c5c3c86f35f19bbc1a8d5541c77c7a952271058545b076d61746f6b656e046c69766500002e00010000012c0120003008020000012c603a54c7601d53c7a8f4076d61746f6b656e046c697665002044b2dc2cfd6f08d327d78ce8fb63761d87acc4a3415ae9d049ed96543d3e3d2ada37d187df0d65a6ae28f5121efff423a48fa0bb343ce2c4b8b67e8e6096529aa3a37ceda76424318222977920d7aa811a4bf2af60a0ca2e135f6079acbf408a1800e039421a3f4d1b2a0815bf82632132c4dd5810f7896d1b9b3c36be4ff968ae568308a6f9144168399f31cb316c66139787a9e37d42b7ffc092fbf300937530b185dcd73e03bdcfe394a9a6ad3e51cce5172a2d17c33cd31aff8c6174b434e4720fd6fc00b7a26b9dfe3b208c532090cd5ba96ee786f665c621dda0aac2d2cd7b6adcb7335cae9f15940c31f67a060c2324788a87c173e2fbf7b90f3b0600002904d0000080000000',
        DS: '000181a00001000200000001076d61746f6b656e046c69766500002b0001076d61746f6b656e046c69766500002b0001000141150024a8f40802161542bba238b97420b4046f9a444baa7316948601b4b041481eb9ee02651cc4076d61746f6b656e046c69766500002e00010001411500b8002b0802000151806047bdd160202ff431fb046c6976650073b70a233076276b619c3dfee8c601574ab5cad657add22fffd71132af0a40dfef0aa85001df437bcf512ac9c417ba21d895f871715280667d5133e1d5ca0061dc2b48caed7969b2636352f0e461bb11fdb21da937e39c5dcefa4efd4096b6985d3ebd1278b39b894143220e20d3509660382433e10877c0cefe9af6895a491473ada28011a2abb192b66bfcaa5c5bc8fcb629e8f402e1aab96dd693ea892fa000002904d0000080000000'
    },
    'live': {
        DNSKEY: '000181a00001000400000001046c6976650000300001046c69766500003000010000266c00a80100030803010001c722eb6cfa08fe96c7b1cb44ba43d464b34cb3122f427627324d534541ae500bc5f675fa0c427f93386e28676325cc8bb2575ea8ae7bdbff28c6a6c8530ebe37c892dafcba999272bdda41f5a4cc92aa1fdb551e839407bb1e43db0c86ac5231069909305c33813d648e470bc377ceac71a0dbba977e80172048132c4eb4345a7d8c95a7d9501bec473d3d6fb97980b63372cd3a618f54a3766739ff705586bf046c69766500003000010000266c01080101030803010001c0f30ddcd08c265628e4a309490bb67068b0235ec406dd1c2aaefd2dd3b4c9422abc1c65cb9e4e5e99609a71e5f31dd4d26e82954c4bc5ba05facbdfee590a8f552adcfe4db73a0da644ffdabe93eec5d7ead2894ac22fe987beec79c1f01b4f29fef2bc7dc79c1cf48f4d5bc874ee1fd73c4c8acad53b52822f73f2ff4d9eaef0f57841ff6edbd55fef1299ae51603239478e67ce1c46bd80a1e29c8038186b0bc0b6696e9cb1c323727f9f5be97916c71dfa5ad5291fadbb30831171aa760ddad157b9c5df6e6d6fbd292d7f424575ee62cd50c5db55db1b10540a83560f65ecd5cf7911a7889a47a3d82eecfd81af2d614115de9700d4ce0a709af50bcb8f046c69766500002e00010000266c00b8003008010001518060487bc26020eae631fb046c697665001e0b2130892e5c0e7cc24ffd09f4035851b7fa7bcd4960f768633eca8b555d36c36d0190e219bd132941316b2d6c74000d80b0651dbf827980789b378b5071d35f5030761bce6c6b18b52e16011ffd889fd03330152d6ef7158f5984094e9b61390208fe57698566e65633c1a55958d8e58645024de1ffeabda678b3e07a2ccc73a3d332e4666d3bbc53a7d5f196dac4753d895d4c3771b6db2d0176639e3077046c69766500002e00010000266c0118003008010001518060487bc26020eae66aa8046c697665003f5eb8e9b3177b7dae45a1900dab26ac2d3c52a32d4c6cea183d033f7dda1807701e7a87e0ca66ede131ef178aac86302e4e9a9b3479a8f8a26d274e511c057154a4486b7503268b7736261411be3610a368f6b6c304e3920679cf1ea9cb1b6a526394f7cce7c458b92dae9d121609d79ca077c6ece056b878c9bafea5b0723a1e263829317e7e417b7097a47a675d2b3c8b8fc5d9076e46a2e284affd5e84db5fb27cbed8b35dcb3907810fc732e73f04707acadb73fc609989178c47a4f238934fe612040d252eb2224e6b098b0a314c04b96f57d57df0326c5b5cc7b3a1c9d128d7114a0b11759ddc30051222d041d1f527131f521b7123351e65a2ab893700002904d0000080000000',
        DS: '000181a00001000300000001046c69766500002b0001046c69766500002b0001000140bb00186aa80801bb1914f4690fdc1c882fa6cea84d14fca6b9d38d046c69766500002b0001000140bb00246aa80802f76b40cac1a4f9d7b2e3ed67602d7f934fd45d9064ce78880fb73d09b1acd107046c69766500002e0001000140bb0113002b0801000151806032d7e06021a650a56f00adf8d064c4f4f4e9246247b2ba9d0d32808292abb9bc27055477439c1ff9705537fad47e135f9509fdc835cff3398018c5db889051a735f9d1800c08d4d23374e35c39115c9c687197fd4ae90ac758fa7103c0cf1f1bd2251b7852ff0dd0f13513cfb955451b803a548e5712b82e2133fb6880e4c70752a7985dd6e3eab267a47c8339fe6eba47715dba511ebf77e623bccb4ea510165482dab5aea968567495bae292df896d10c3c409f960a64f6d27ad4dc8bea787ad3f0b90eedba7a29848c52a8df93637f930238f4c884b350a0ed5bbdd2e48054093661f0411ca14924306ea6ef2a6c47c59e6d06d9406242aafcbabb27c8c13859e3588c236263d526800002904d0000080000000'
    },
    '.': {
        DNSKEY: '000181a00001000300000001000030000100003000010000008401080100030803010001b2862a4a9cd5502f42be3c88f7fd35ddfd7f7dfb322b60831174001f642ca44d4aeabd8e83843c2fd1e8f0ffe254f3526b3c53da0ff9a885d2b542dab18e29274e2f13c744b0376a678c153dbfddb995085b11b27d372154dd37955401f7338ea8e6034b7d34cedb6cde68573b902f73f517241bd6ae875f8335aa0fa1b4c34477d3dd94f2cc15cad48397dc62d4ebda595590ed57a3794076b8e69b17c6788c909ec929c0fc96f3c279dbb0c4cad9a03e8e4accb0582cca0bd90e353cad2e974aecef237e839206e0b9c939c8dec35cab9875eba7f3b3ae9b0ee0592272e7d8b7fca07d02a44f91d86ebff216079901f685f349d8c9cef080363139e1dd891900003000010000008401080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500002e0001000000840113003008000002a3006031a2806015f3004f660081046d9658b71d69065623c30e3a0530acad66ae4d61762843ab77e91f4517305b9ec1017f63b7e415e1d8d8f99670a887a87fb359ef4f1a1bd6421831a8b816057078573b8b414e21254206ced056bbf1334f00b71ac99d2c15f84aa2c5412bc474f7da88d0849ac50bd31b1a7a3582c1a55f4852be3517711b40dbca5c19c8239e5703556c6d6e6f4c5a5ba59c006248649d3b9132dcc3860c7925967ae7996298eb147fcaf345745a87c4fb52d2803c887fba55d2bb8b1d1064d79c2d1ce89bee6cc7d4a3af0fc92499573c45021fa283684d7473a07ae699485e698b6196ab13a21fd1961767e124eea0ae14724ed612364687d6a253c4ffdb825aed2ed100002904d0000080000000'
    }
};

chai.use(chaiAsPromised);

function makeProver(responses: {[qname: string]: {[qtype: string]: string}}) {
    const sendQuery = function(q: packet.Packet): Promise<packet.Packet> {
        if(q.questions.length !== 1) {
            throw new Error("Queries must have exactly one question"); 
        };
        const question = q.questions[0];
        const response = responses[question.name]?.[question.type];
        if(response === undefined) {
            throw new Error("Unexpected query for " + question.name + " " + question.type);
        }
        return Promise.resolve(Object.assign(packet.decode(Buffer.from(response, 'hex')), {questions: q.questions, id: q.id}));
    };
    return new DNSProver(sendQuery);
}

function encodeAnchors(): Buffer {
    const buffers = new Array<Buffer>(DEFAULT_TRUST_ANCHORS.length);
    for(let i = 0; i < buffers.length; i++) {
        buffers[i] = packet.answer.encode(DEFAULT_TRUST_ANCHORS[i]);
    }
    return Buffer.concat(buffers);
}

function decodeProofs(data: Buffer): SignedSet<any>[] {
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

function decodeRrset(data: Buffer): packet.Answer[] {
    const rrs = [];
    let off = 0;
    while(off < data.length) {
        rrs.push(packet.answer.decode(data, off));
        off += packet.answer.decode.bytes;
    }
    return rrs;
}

describe('dnsoraclejs', async () => {
    const algorithms: {[key: string]: Contract} = {};
    const digests: {[key: string]: Contract} = {};
    let oracleContract: Contract;

    before(async () => {
        const RSASHA256Algorithm = await ethers.getContractFactory("RSASHA256Algorithm");
        algorithms[8] = await RSASHA256Algorithm.deploy();
        const P256SHA256Algorithm = await ethers.getContractFactory("P256SHA256Algorithm");
        algorithms[13] = await P256SHA256Algorithm.deploy();
        const DummyAlgorithm = await ethers.getContractFactory("DummyAlgorithm");
        algorithms[253] = await DummyAlgorithm.deploy();

        const SHA1Digest = await ethers.getContractFactory("SHA1Digest");
        digests[1] = await SHA1Digest.deploy();
        const SHA256Digest = await ethers.getContractFactory("SHA256Digest");
        digests[2] = await SHA256Digest.deploy();
        const DummyDigest = await ethers.getContractFactory("DummyDigest");
        digests[253] = await DummyDigest.deploy();
    });

    beforeEach(async () => {
        const DNSSECImpl = await ethers.getContractFactory("DNSSECImpl");
        oracleContract = await DNSSECImpl.deploy(encodeAnchors());
        for(let id of Object.keys(algorithms)) {
            await oracleContract.setAlgorithm(id, algorithms[id].address);
        }
        for(let id of Object.keys(digests)) {
            await oracleContract.setDigest(id, digests[id].address);
        }
    });

    it('processes a real record on TXT _ens.matoken.live correctly', async () => {
        const oracle = new Oracle(oracleContract.address, ethers.provider);

        const prover = makeProver(MATOKEN_1);
        const queryResult = await prover.queryWithProof('TXT', '_ens.matoken.live');
        const {data, proof} = await oracle.getProofData(queryResult);

        const decodedData = decodeProofs(data);
        const proofrrset = decodeRrset(proof);
        expect(decodedData.length).to.equal(6);
        expect(proofrrset[0].type).to.equal('DS');
        expect(proofrrset[0].name).to.equal('.');

        const tx = await oracleContract.submitRRSets(data, proof);
        await tx.wait();
    });

    it('only updates changed fields on _ens.matoken.live', async () => {
        const oracle1 = new Oracle(oracleContract.address, ethers.provider);

        const prover1 = makeProver(MATOKEN_1);
        const queryResult1 = await prover1.queryWithProof('TXT', '_ens.matoken.live');
        const result1 = await oracle1.getProofData(queryResult1);
        const tx1 = await oracleContract.submitRRSets(result1.data, result1.proof);
        await tx1.wait();

        // Wait 301 seconds and try again
        const oracle2 = new Oracle(oracleContract.address, ethers.provider, () => 1612868724000);
        const prover2 = makeProver(MATOKEN_1);
        const queryResult2 = await prover2.queryWithProof('TXT', '_ens.matoken.live');
        const result2 = await oracle2.getProofData(queryResult2);

        await ethers.provider.send('evm_increaseTime', [301]);

        const decodedData = decodeProofs(result2.data);
        const proofrrset = decodeRrset(result2.proof);
        expect(decodedData.length).to.equal(2);
        expect(proofrrset[0].type).to.equal('DS');
        expect(proofrrset[0].name).to.equal('matoken.live');

        const tx2 = await oracleContract.submitRRSets(result2.data, result2.proof);
        await tx2.wait();
    });
});