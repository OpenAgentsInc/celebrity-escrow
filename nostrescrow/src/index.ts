import {SimplePool, nip04, nip19, Event, getPublicKey, getEventHash, signEvent} from 'nostr-tools'
import {sha256} from '@noble/hashes/sha256'
import { bytesToHex } from '@noble/hashes/utils';

const utf8Encoder = new TextEncoder()


function assert(ok: boolean, msg: string) {
  if (!ok) throw Error(msg)
}

interface SubsetContract {
  escrow_pub: string;
  maker_sats: number;
  taker_sats: number;
  escrow_sats: number;
  contract_text: string;
  maker_sig: string;
}

interface MakerContractParams extends SubsetContract {
  maker_nsec: string;
  taker_pub: string;
}

interface TakerAcceptParams {
  taker_nsec: string;
  maker_pub: string;
  event_id: string;
  taker_sig: string;
}

interface FullContract extends SubsetContract{
  maker_pub: string;
  taker_pub: string;
  taker_sig?: string
}

const DEFAULT_RELAYS =  [
  'wss://relay.damus.io/',
  'wss://relay.nostr.bg/',
  'wss://nostr.fmt.wiz.biz/',
  'wss://relay.nostr.band/',
  'wss://nos.lol/'
]

export class NostrEscrow {
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
    const { type, data } = nip19.decode(nsec);
    assert(type == "nsec", "invalid nsec");
    const priv = data as string;
    const sub = await this.pool.get(this.relays, { ids: [event_id] });

    if (!sub) throw Error("unknown contract");

    const taker_tag = sub.tags.find((el) => {
      return el[0] == "p";
    });
    if (!taker_tag) throw Error("taker pub unknown");
    const taker_pub = taker_tag[1];

    const maker_pub = sub.pubkey;

    const taker_reply = await this.pool.get(this.relays, { "#e": [event_id], authors: [taker_pub] });

    let plain: string;
    let plain_reply: string| null = null;
    if (role == "taker") {
      console.log(priv, maker_pub, sub.content)
      plain = await nip04.decrypt(priv, maker_pub, JSON.stringify(sub.content));
      if (taker_reply)
        plain_reply = await nip04.decrypt(priv, maker_pub, JSON.stringify(taker_reply.content));
    } else if (role == "maker") {
      plain = await nip04.decrypt(priv, taker_pub, JSON.stringify(sub.content));
      if (taker_reply)
        plain_reply = await nip04.decrypt(priv, taker_pub, JSON.stringify(taker_reply.content));
    } else {
      throw Error("only maker or taker can view the original contract");
    }

    const [
      ver,
      escrow_pub,
      maker_sats,
      taker_sats,
      escrow_sats,
      contract_text,
      maker_sig,
    ] = JSON.parse(plain);

    assert(ver == 0, "invalid contract ");

    let taker_sig = null

    if (plain_reply) {
      const [
        ver,
        sig,
      ] = JSON.parse(plain_reply);
      assert(ver == 0, "invalid contract ");
      taker_sig = sig
    }

    return {
      maker_pub: maker_pub,
      taker_pub: taker_pub,
      escrow_pub: escrow_pub,
      maker_sats: maker_sats,
      taker_sats: taker_sats,
      escrow_sats: escrow_sats,
      contract_text: contract_text,
      maker_sig: maker_sig,
      taker_sig: taker_sig
    };
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
    return await this.publishAndWait(ev)
  }

  async acceptContract(contract: TakerAcceptParams): Promise<Event> {
    const ev = await this.createAcceptEvent(contract);
    return await this.publishAndWait(ev)
  }

  async createAcceptEvent(params: TakerAcceptParams): Promise<Event> {
    const [taker_priv, taker_pub] = this.getPrivPub(params.taker_nsec);
    const ev = {
      kind: 3333,
      tags: [
        ["e", params.event_id],
      ],
      content: await nip04.encrypt(
        taker_priv,
        params.maker_pub,
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

    const ev = {
      kind: 3333,
      tags: [
        ["p", params.taker_pub],
        ["hash", subcontract_hash],
      ],
      content: await nip04.encrypt(
        maker_priv,
        params.taker_pub,
        subcontract_serial
      ),
    };

    return this.signEvent(ev, maker_pub, maker_priv);
  }

  private signEvent(ev: { kind: number; tags: string[][]; content: string; }, pub: string, priv: string) : Event {
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
    return [priv, pub ];
  }
}

