import {SimplePool, nip04, nip19, Event, getPublicKey, getEventHash, signEvent} from 'nostr-tools'
import {sha256} from '@noble/hashes/sha256'
import { bytesToHex, randomBytes } from '@noble/hashes/utils';
import {secp256k1, schnorr} from '@noble/curves/secp256k1'
import {base64} from '@scure/base'
import { numberToBytesBE } from '@noble/curves/abstract/utils';

const utf8Encoder = new TextEncoder()
const utf8Decoder = new TextDecoder()


function assert(ok: boolean, msg: string) {
  if (!ok) throw Error(msg)
}


interface SubsetContract {
  escrow_pub: string;
  maker_sats: number;
  taker_sats: number;
  escrow_sats: number;
  contract_text: string;
  maker_sig: string;    // unused until op_ctv or similar allows for reduced interactivity
}

interface MakerContractParams extends SubsetContract {
  maker_nsec: string;
  taker_pub: string;
}

interface TakerAcceptParams {
  taker_nsec: string;
  maker_pub: string;
  contract_hash: string;
  event_id: string;
  taker_sig: string[];
}

interface FullContract extends SubsetContract{
  maker_pub: string;
  taker_pub: string;
  contract_hash: string
  shared_secret: string
  taker_sig?: string[]
}

const DEFAULT_RELAYS =  [
  'wss://relay.damus.io/',
  'wss://relay.nostr.bg/',
  'wss://nostr.fmt.wiz.biz/',
  'wss://relay.nostr.band/',
  'wss://nos.lol/'
]

class NostrEscrow {
  relays: string[];
  pool: SimplePool;
  constructor() {
    this.relays = DEFAULT_RELAYS;
    this.pool = new SimplePool();
  }

  async setRelays(relays: string[]) {
    this.relays = relays;
    await Promise.all(
      relays.map((url) => {
        this.pool.ensureRelay(url);
      })
    );
  }

  async getContract(
    role: string,
    nsec: string,
    event_id: string
  ): Promise<FullContract> {
    const is_escrow = role == "escrow"

    const { type, data } = !is_escrow ? nip19.decode(nsec) : {type: null, data: nsec}

    assert(is_escrow || type == "nsec", "invalid nsec");

    const priv = data as string;
    const sub = await this.pool.get(this.relays, { ids: [event_id] });

    if (!sub) throw Error("unknown contract");

    const taker_tag = sub.tags.find((el) => {
      return el[0] == "p";
    });
    if (!taker_tag) throw Error("taker pub unknown");
    const taker_pub = taker_tag[1];

    const maker_pub = sub.pubkey;

    const taker_reply = await this.pool.get(this.relays, {
      "#e": [event_id],
      authors: [taker_pub],
    });

    const { shared_secret, plain, plain_reply, contract_hash } = await this.decryptAs(
      role,
      priv,
      maker_pub,
      taker_pub,
      sub,
      taker_reply?.content,
    );

    const subcontract_serial = JSON.parse(plain);

    const [
      ver,
      escrow_pub,
      maker_sats,
      taker_sats,
      escrow_sats,
      contract_text,
      maker_sig,
    ] = subcontract_serial;

    const confirm_hash = bytesToHex(
      sha256(utf8Encoder.encode(plain))
    );

    if (contract_hash) {
        assert(contract_hash == confirm_hash, "contract hash does not match, aborting")
    } else {
        assert(role == "escrow", "taker and maker must have access to the contract hash")
    }

    assert(ver == 0, "invalid contract ");

    let taker_sig = null;

    if (plain_reply) {
      const [ver, sig] = JSON.parse(plain_reply);
      assert(ver == 0, "invalid contract ");
      taker_sig = sig;
    }

    return {
      maker_pub,
      taker_pub,
      escrow_pub,
      maker_sats,
      taker_sats,
      escrow_sats,
      contract_text,
      maker_sig,
      taker_sig,
      contract_hash: confirm_hash,
      shared_secret,
    };
  }

  public async getHashFromEvent(priv: string, pub: string, sub: Event) {
    const contract_tag = sub.tags.find((el) => {
      return el[0] == "hash";
    });
    if (!contract_tag)
      throw Error("contract hash unknown");
    const encrypted_hash = contract_tag[1];
    const contract_hash = await nip04.decrypt(priv, pub, encrypted_hash)
    return contract_hash;
  }

  async getContractSecretFromEvent(
    nsec: string,
    pub: string,
    sub: Event,
  ) {
    const { type, data } = nip19.decode(nsec);
    assert(type == "nsec", "need nsec")
    return this.getContractSharedSecret(data as string, pub, await this.getHashFromEvent(data as string, pub, sub))
  }

  async getContractSharedSecret(
    priv: string,
    pub: string,
    contract_hash: string
  ) {
    const tweaked_pub = this.tweakPub(pub, contract_hash);
    const shared_secret = base64.encode(
        secp256k1.getSharedSecret(priv, "02" + tweaked_pub).slice(1, 33)
    );
    return shared_secret
  }

  async decryptAs(
    role: string,
    priv: string,
    maker_pub: string,
    taker_pub: string,
    sub: Event,
    taker_reply?: string,
  ) {
    let shared_secret, plain, plain_reply, contract_hash;
    let content = sub.content
    
    if (role == "taker") {
      contract_hash = await this.getHashFromEvent(priv, maker_pub, sub);
      const tweaked_pub = this.tweakPub(maker_pub, contract_hash);
      await decryptWith(tweaked_pub);
    } else if (role == "maker") {
      contract_hash = await this.getHashFromEvent(priv, taker_pub, sub);
      const tweaked_pub = this.tweakPub(taker_pub, contract_hash);
      await decryptWith(tweaked_pub);
    } else {
      shared_secret = priv;
      plain = await this.decryptWithSharedSecret(shared_secret, content);
      plain_reply = await this.decryptWithSharedSecret(shared_secret, taker_reply);
    }
    return { shared_secret, plain, plain_reply, contract_hash };

    async function decryptWith(tweaked_pub: string) {
      shared_secret = base64.encode(
        secp256k1.getSharedSecret(priv, "02" + tweaked_pub).slice(1, 33)
      );
      plain = await nip04.decrypt(priv, tweaked_pub, content);
      if (taker_reply)
        plain_reply = await nip04.decrypt(
          priv,
          tweaked_pub,
          taker_reply
        );
    }
  }

  async decryptWithSharedSecret(
    shared_secret: string,
    content: string
  ): Promise<string> {
    if (!content) return ""

    const bytes_key = base64.decode(shared_secret);

    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      bytes_key,
      { name: "AES-CBC" },
      false,
      ["decrypt"]
    );
    const [ctb64, ivb64] = content.split("?iv=");
    const ciphertext = base64.decode(ctb64);
    const iv = base64.decode(ivb64);

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      cryptoKey,
      ciphertext
    );

    return utf8Decoder.decode(plaintext);
  }

  async publishAndWait(ev: Event): Promise<Event> {
    const sub = this.pool.publish(this.relays, ev);
    return new Promise<Event>((res) => {
      sub.on("ok", () => {
        res(ev);
      });
    });
  }

  async createContract(contract: MakerContractParams): Promise<Event> {
    const ev = await this.createContractEvent(contract);
    return await this.publishAndWait(ev);
  }

  async acceptContract(contract: TakerAcceptParams): Promise<Event> {
    const ev = await this.createAcceptEvent(contract);
    return await this.publishAndWait(ev);
  }

  async createAcceptEvent(params: TakerAcceptParams): Promise<Event> {
    const [taker_priv, taker_pub] = this.getPrivPub(params.taker_nsec);
    const tweaked_pub = this.tweakPub(params.maker_pub, params.contract_hash);
    const ev = {
      kind: 3333,
      tags: [["e", params.event_id]],
      content: await nip04.encrypt(
        taker_priv,
        tweaked_pub,
        JSON.stringify([0, params.taker_sig])
      ),
    };
    return this.signEvent(ev, taker_pub, taker_priv);
  }

  async createContractEvent(params: MakerContractParams): Promise<Event> {
    const [maker_priv, maker_pub] = this.getPrivPub(params.maker_nsec);

    const subcontract: SubsetContract = {
      escrow_pub: params.escrow_pub,
      maker_sats: params.maker_sats,
      taker_sats: params.taker_sats,
      escrow_sats: params.escrow_sats,
      contract_text: params.contract_text,
      maker_sig: params.maker_sig,
    };

    const subcontract_serial = JSON.stringify([
      0,
      subcontract.escrow_pub,
      subcontract.maker_sats,
      subcontract.taker_sats,
      subcontract.escrow_sats,
      subcontract.contract_text,
      subcontract.maker_sig,
    ]);
    const subcontract_hash = bytesToHex(
      sha256(utf8Encoder.encode(subcontract_serial))
    );

    const tweaked_pub = this.tweakPub(params.taker_pub, subcontract_hash);
    const encrypted_hash = await nip04.encrypt(maker_priv, params.taker_pub, subcontract_hash)

    const ev = {
      kind: 3333,
      tags: [
        ["p", params.taker_pub],
        ["hash", encrypted_hash],
      ],
      content: await nip04.encrypt(maker_priv, tweaked_pub, subcontract_serial),
    };

    return this.signEvent(ev, maker_pub, maker_priv);
  }

  private tweakPub(pub: string, hex: string) {
    const pt = secp256k1.ProjectivePoint.fromHex("02" + pub);
    const hash_bn = BigInt("0x" + hex)
    let tweaked = pt.multiply(hash_bn).toHex();
    return tweaked.slice(2);
  }

  public tweakAddPub(pub: string, hex: string) {
    const hash_bn = BigInt("0x" + hex)
    const pt = secp256k1.ProjectivePoint.fromHex("02" + pub);
    const one = secp256k1.ProjectivePoint.fromPrivateKey(BigInt(1));
    const mult = one.multiply(hash_bn)
    let tweaked = mult.add(pt);
    // this could be negating
    return tweaked.toHex().slice(2);
  }

  public tweakAddPriv(priv: string, hex: string) {
    if (secp256k1.ProjectivePoint.fromPrivateKey(priv).toHex().startsWith("03")) {
      // we had negated the pub
      const pinv = secp256k1.CURVE.Fp.sub(secp256k1.CURVE.n, secp256k1.utils.normPrivateKeyToScalar(priv))
      priv = bytesToHex(numberToBytesBE(pinv, 32)) 
    }
    const hash_bn = BigInt("0x" + hex)
    const pnum = secp256k1.CURVE.Fp.add(BigInt("0x" + priv), hash_bn)
    const pt = secp256k1.ProjectivePoint.fromPrivateKey(pnum);
    if (pt.toHex().startsWith("03")) {
        const inum = secp256k1.CURVE.Fp.sub(secp256k1.CURVE.n, pnum)
        return bytesToHex(numberToBytesBE(inum, 32))
    }
    return bytesToHex(numberToBytesBE(pnum, 32))
  }

  private signEvent(
    ev: { kind: number; tags: string[][]; content: string },
    pub: string,
    priv: string
  ): Event {
    const created_at = Math.floor(Date.now() / 1000);
    const tmp = { ...ev, created_at: created_at, pubkey: pub };
    const ret = {
      ...tmp,
      id: getEventHash(tmp),
      sig: signEvent(tmp, priv),
    };
    return ret;
  }

  private getPrivPub(nsec: string) {
    const { type, data } = nip19.decode(nsec);
    assert(type == "nsec", "invalid nsec");
    const priv = data as string;
    const pub = getPublicKey(priv);
    return [priv, pub];
  }

  close() {
    this.pool.close(this.relays)
  }
}


export default NostrEscrow
