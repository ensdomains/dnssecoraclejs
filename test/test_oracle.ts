import * as packet from 'dns-packet';
import * as chai from 'chai';
import { expect } from 'chai';
import * as chaiAsPromised from 'chai-as-promised';
import { ethers } from 'hardhat';
import { Contract } from 'ethers';
import { dohQuery, DNSProver, SignedSet, DEFAULT_TRUST_ANCHORS } from '@ensdomains/dnsprovejs';

import { Oracle, RRSetWithSignature } from '../src/oracle';

const MATOKEN_1 = {
    "_ens.matoken.xyz": {
        "TXT": "000181a00001000200000001045f656e73076d61746f6b656e0378797a0000100001045f656e73076d61746f6b656e0378797a0000100001000000e7002d2c613d307835413338343232374236354641303933444543303345633334653131314462383041303430363135045f656e73076d61746f6b656e0378797a00002e0001000000e7009f001008030000012c60f43b5b60d73a5bbb4e076d61746f6b656e0378797a00121c450b02d8d2cef60692c433dbbcb34aba1bebcb3f5db50fe2afb087db53180afc99e79193324790bb265680a0affa9c235a2d7877179a116b4bc0313455259c971f669718ba4c2a89e9ccdecefb67743fa4f071e81d066834e2d97984abca163d0c42ce9755e0307a6e769a13759930b5c621688c97d24e21096484cfa36100002904d0000080000000"
    },
    "matoken.xyz": {
        "DNSKEY": "000181a00001000300000001076d61746f6b656e0378797a0000300001076d61746f6b656e0378797a0000300001000000b9008801000308030100019581460a1d0e20ff863a2fab3986df9286e51855fc9886bba86121cff5e0162bdff5e991eca35e08c52f6e5835e701afff02c8bc6bb57b4ae26fc3ed32d961332609f41da367e1ebbfc77e5c1b4a55264039c7abbfb539948245ba399129a881d2a1860c074205ae301a9974c85cf15252954d38e8c0f7d7459209cbfd88eed1076d61746f6b656e0378797a0000300001000000b901080101030803010001a50f4f96bb0a1e5c4d591c80356b7fd14233108c03eecc700cf6c78f77dcdf1d16aa82fbd387e32030a105be5635f32c5e296f0e26747b895cc48368dd48d18aeb82511f2adc1a1f935a7095b850ca3217d316e460284b45e8673c3621238e38f08ea6185075cd13f527c6e6948f4efbcf3173999bd28547df5cfa3880c13e268c9bade7632eedbe48e27b140ca4019ce9c316de1f0efd8339223ec956dd0b4b305f46d95d20f7f36197e3e55a94d7fa623cfc6b5486b5a6e4bf9fcf4e5331687530aaa7acaa33156299d0d49edb67197399f04b7e4e40d61a521bc90134cfd9154b2a44dcfef2738e454bec36b6d02e42048df76e08e5336badf438dde2be91076d61746f6b656e0378797a00002e0001000000b9011f003008020000012c60f43b5b60d73a5b90b2076d61746f6b656e0378797a002d42467b02ccb9844923a17ff91ed31c445fddcaf8df12c343bb5ed2e3f91df19d7bd7b1179565944577972330ed5aafb5425ef65dbae0eff2111b043a84fabd23d5b6552c4c10e5a66faeb55a2f75fed41284c21374f537867727811cd91b6578e27025f791a70cceb0678171b8ea7ee66ba5fa06fd21734a3d74d28b4b24a7d3e84274c28d4a91dd36d9495b0aa859542792bbc1f9be5dd48a66f12302fcdc5d487f8dfebb53afe0aa401cbaf2ca8dfab94bba4df16ecc6d2946623510809b1c0a006ae93b188cddc400b94dad4770a4dcc454a86b7bf344598f410b5433d9c5da447a8584379d91ee5b149177a3604cef32adb43b41d83790cc6bda958dca00002904d0000080000000",
        "DS": "000181a00001000200000001076d61746f6b656e0378797a00002b0001076d61746f6b656e0378797a00002b000100000ddd002490b20802cf2a174c557308595dbf1039b0c5999037d04b2e764c48bd55bdc1cd48eab8ca076d61746f6b656e0378797a00002e000100000ddd0097002b080200000e1060e7ccb560bf8af8c4fc0378797a0059194122794883c78cffcae50bfe70eecf9d3934ce53d733678125de350ed12197ffe39cd0d128a5c3ca8a399a373db694a78e8ee79fd45743a0aba3e02f3dc44a4b365dd8d5c84a8b2e85bc9532f7908375bb6785dcd07de907ed97c6433bb053759f3ef25dd3a09c9497393c066e4606b47a14455e6a81bec92e590301311300002904d0000080000000"
    },
    "xyz": {
        "DNSKEY": "000181a000010005000000010378797a00003000010378797a000030000100000bd000880100030803010001b6a9e039f10230afef1992b3eb2eb6521618a9e2a9170451acea7030c55230830c7c25e370ab839555b67fadc298c51ec64afad5b9c24974e36409dac12e513035a18698343725ae099692be1caf0e2ad820a06b679506d6bc2b6efb3783242be1edc410170f2cc4ad7f09d155cb2762bfa1176c17b33433447b64182f7069670378797a000030000100000bd000880100030803010001b8a384809a77ddb0db5d540b7a11ccf9565739d03f05cb7e7ef5a469846b01d03c9c3c30d5b5c53b62d4958f70315140362921eba2ea90fe81e1b89d5eaec1b99144c8eefc9d4774f6af5cc417c91e138e69f0b497fa976fdb6627abe26fa0c3d8f72fb412d1f951be05f82fd8f07a286c5df3bfdc5f7c78a6f8662b8bcc39cd0378797a000030000100000bd000880100030803010001e9f7e6b0770c6304c791d2f2c9ac0c4824dbc8477e6273271c18a7c0fb6167836c91c46874792dbc6e5944e8c49f2003c152cdfdb144ac27501f583e6ecb5e7ffb7ba516407bad17590e35593fe861f53656bb4993c6d740915e0393929225f7ad665b91154594296649b82249cfa1916a3fc0aed711be8f9b4e78f9ca200c210378797a000030000100000bd001080101030803010001b6114f39202e0e28c5c15bffea0540cbe5b84bade39b224ed2e234beede458a6fd99d8864c5a97a4e2094cb09df822c9c2729de366b42ff77a84dccf9765ae5441e5dc037a172a899a058aa8da5c61dcca41c61410f29c3d3fb117040102fe6cb32fdaa03ea362fba433c76c2189557954ab9ee84d67d2e1eb1b18321afb506cf200d530651971b46679e2a473f307d8eab502913910a8c7d1946f6164ba69fb16caf9570f63570ed852e4b96d54aaaa8e18ba772d8ed36b2d3ade35cf5ab07d1954f3d6f71d77c3821949fcbdf70c4f8e713c8ad32449f9acb85a90604092fc18314acf586747694e8d85cbb6d243eda1df718c953bacd8b31d9a78723439830378797a00002e000100000bd001170030080100000e1060ff649260d79ad40e0f0378797a001c734b64c9cf17d81c7c38f2bf0631fb7a287d3465c3cece8370ae80559ea9829c8ed41ff9eef61a5e87e70561e44a6ddf190bc4debf68ebdd6d8b416bf16d0959bf0bc68de44df59d985442ce9e6532de73a9f80da07e9633cd6b4657269729b7b571eb87ca9579ded37e3da5db5eb32c3a39428e9ffa345a2fe47965ff1c8beef97f4af2a2c111012a640054940a7d704d60bfa4d39be4263ea9e1d1d3d2f02382f375e01efb6ef863358176fa1174e180bb550e404d54a4f3b4467915ebd2e4e2ac5c281a93de2020d9b95e98415d4ca9cac494684d9e36ccd8f2689d5f960a71d17f4026daf0b0f372e793c0165bf6b6e2755ecaa5117e7dc54b7726da8700002904d0000080000000",
        "DS": "000181a000010003000000010378797a00002b00010378797a00002b000100014ded00180e0f08013fa3b264f45db5f38bedeaf1a88b76aa318c2c7f0378797a00002b000100014ded00240e0f0802b9733869bc84c86bb59d102ba5da6b27b2088552332a39dcd54bc4e8d66b04990378797a00002e000100014ded0113002b08010001518060eb5bd060da2a4039270043a9f89e2577a4f42ee7c3ee7e46c583da2691dbcb127c70190a4e6b959e779061ddebc7ac7eaf7034c9df00ed549498798a180f62841f16dd26aba4684e6dd5d87ac18b71f9b28f1607ab7506a83377cf6db8a61ea9b141727b745514f22e3673493d621910eee6c0aca92eea5a0c341c9bd275da8b76446a294e42464bb9369bde3ed53fe3ebc4ca5d3e3f5444e2c87793119b859c66eb94b5cc6735cdd86bb65f7daa7ca569c7c490bc72d907e92a7248299d9d0e11463fbc19bd8a81768a183e2c68714f2a09356e1cf370b38ac1c699a30e53d2bd15dfaaec249c6f61a6d3f8b66b589694116d3edffb7b57ef86c0064649ae8b3200b2d07a301a3fface00002904d0000080000000"
    },
    ".": {
        "DNSKEY": "000181a00001000400000001000030000100003000010000019801080100030803010001af87bc3ed75e398bfb586d4e1510c995bba161a78f32872404a0dd3491e419aee4b7e74955bb7f1a996b6a00628da2a272105b2a808ff968029ce0f0634c8722226dfb4f26ca39e2e59143619aa0caf02c3e522eeebbea47fbbab26aea7a9d8cd0b468933f0bcf3c962ebd9551fab62bb6b599b5347ddc9a07e73142690fad1bb2b0d4aaced7c1fb663647641dae25b506ccdd434fc9f4da341418a07df0a4ea528dd937b720d19eb7813ba21daf0f8319ffebbdee2c2f7aa249a5df60891cc00c28cf1477e221d4e5d6c20ecf12e85999621a1254a560352524b9dc6177dffa46b66461182fc11b105e5dd4c2c69c5350ec5dc391a880beecd950e8cd8e255500003000010000019801080100030803010001b0c4caa770bb67ea0308a73c217000b50259f61868bacd8673ab3310e8acb058322a441356ed94ad579e281344c79bd1843cfcb0a8a5bdc237bde16038421c5b0d93e1adba4041fa058b720fb61595db84b5c885e426f31d957ce1f2db26101bed7cc23c771d8f4c8ff6448576d936b0ccbe914a2958a15976b4fdc1cd83865c2070fd2a43252b32be9b2d4afefcfc7eae5c14214ebbbc2033e90a6ce8a475c4419bb51fff0457648b45836ba15228d46f9ea010df2e094826b84c3ac10e5906e47b513fc52f2c8051e007f3ba311788a6d835cae89f8903b200b36507275eae4eabddb1ead453c348a2c8ac95a5c8642bf3f8d4c36f7489731b3a6ef0a291e500003000010000019801080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500002e0001000001980113003008000002a30060ea348060ce85004f6600a786e146e849f734fdd732788a1557ed513844845d54e97f35f4f6a4992f6f6f2b5ac605751574dd1a54779594f53fe7d97929cd0b049d697d16b1a9c978f2e50dd86b6ac881788b869e079fea804a437f53842c1bd7cef40a0c898403271062e351f148828455c6f9b59a7dc9b9a86c5c8ae769b75fe6b6436c2970b158dc9161a3eca6661e588c310c4a14e91567072dba0eeff824e47e8b726a7d10dcfdd0b2120615cf6c7d05217d17ff567fda13a19296f6227437e38928d24f98aa61f8db6941f49a2c93c9e485e633442cea771a663a136a974a63077a238eb57a75eb4b524942392d6f3596435bb0fe049e62be0dd294dca3af3d0fe7fb5abae8329600002904d0000080000000"
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

function decodeProofs(proofs: RRSetWithSignature[]): SignedSet<any>[] {
    return proofs.map((proof) => SignedSet.fromWire(proof.rrset, proof.sig));
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

// The code below is used to fetch real data to provide to the test cases.
// async function getQueryData(qtype: string, qname: string) {
//     const queries:any = {};
//     const sendQuery = dohQuery("https://cloudflare-dns.com/dns-query");
//     const prover = new DNSProver(async (q: packet.Packet) => {
//         const a = await sendQuery(q);
//         if(queries[q.questions[0].name] === undefined) {
//             queries[q.questions[0].name] = {};
//         }
//         queries[q.questions[0].name][q.questions[0].type] = packet.encode(a).toString('hex');
//         return a;
//     });
//     const result = await prover.queryWithProof(qtype, qname);
//     return {result, queries};
// }

// describe('real proofs', async () => {
//     it.only('fetches real proofs for _ens.matoken.xyz', async () => {
//         const {result, queries} = await getQueryData('TXT', '_ens.matoken.xyz');
//         console.log(`Leaf record expires: ${new Date(result.answer.signature.data.expiration * 1000).toString()}`);
//         console.log(JSON.stringify(queries, null, 2));
//     });
// });

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
        const queryResult = await prover.queryWithProof('TXT', '_ens.matoken.xyz');
        const {rrsets, proof} = await oracle.getProofData(queryResult);

        const decodedData = decodeProofs(rrsets);
        const proofrrset = decodeRrset(proof);
        expect(decodedData.length).to.equal(6);
        expect(proofrrset[0].type).to.equal('DS');
        expect(proofrrset[0].name).to.equal('.');

        const tx = await oracleContract.submitRRSets(rrsets, proof);
        await tx.wait();
    });

    // Uncomment once we have real data with an expired signature for _ens.matoken.xyz.
    // it('only updates changed fields on _ens.matoken.xyz', async () => {
    //     const oracle1 = new Oracle(oracleContract.address, ethers.provider);

    //     const prover1 = makeProver(MATOKEN_1);
    //     const queryResult1 = await prover1.queryWithProof('TXT', '_ens.matoken.xyz');
    //     const result1 = await oracle1.getProofData(queryResult1);
    //     const tx1 = await oracleContract.submitRRSets(result1.rrsets, result1.proof);
    //     const receipt = await tx1.wait();

    //     // Wait until the record expires and try again
    //     const nextTs = 1614435828;
    //     await ethers.provider.send('evm_setNextBlockTimestamp', [nextTs]);

    //     const oracle2 = new Oracle(oracleContract.address, ethers.provider, () => nextTs * 1000);
    //     const prover2 = makeProver(MATOKEN_1);
    //     const queryResult2 = await prover2.queryWithProof('TXT', '_ens.matoken.xyz');
    //     const result2 = await oracle2.getProofData(queryResult2);

    //     const decodedData = decodeProofs(result2.rrsets);
    //     const proofrrset = decodeRrset(result2.proof);
    //     expect(decodedData.length).to.equal(2);
    //     expect(proofrrset[0].type).to.equal('DS');
    //     expect(proofrrset[0].name).to.equal('matoken.xyz');

    //     const tx2 = await oracleContract.submitRRSets(result2.rrsets, result2.proof);
    //     await tx2.wait();
    // });
});