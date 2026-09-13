// Anchoring layer: the local development chain, reached over JSON-RPC.
//
// Talks to a node such as `npm run chain` (Hardhat 2, in-memory) at ANCHOR_RPC_URL.
// Transactions are sent from the node's first unlocked development account, so this
// application never holds a chain private key. That is acceptable only because the chain is
// local and worthless; anchoring to a public chain would need a signing key under proper
// custody, which is not implemented.
import {
  BaseError,
  ContractFunctionRevertedError,
  HttpRequestError,
  TimeoutError,
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  type Abi,
  type Address,
  type Hex,
} from "viem";
import artifact from "@/lib/anchoring/anchor-contract.json";
import { HttpError } from "@/lib/errors";

export const DEFAULT_ANCHOR_RPC_URL = "http://127.0.0.1:8545";
export const ANCHOR_ABI = artifact.abi as Abi;

export function anchorRpcUrl(): string {
  return process.env.ANCHOR_RPC_URL || DEFAULT_ANCHOR_RPC_URL;
}

/** No chain answers, or it stopped answering. Anchoring is unavailable, not failed. */
export class ChainUnavailableError extends HttpError {
  readonly status = 503;
  constructor(message: string) {
    super(message);
    this.name = "ChainUnavailableError";
  }
}

/** The chain answered and refused, or the recorded contract is not the anchor contract. */
export class AnchorRejectedError extends HttpError {
  readonly status = 409;
  constructor(message: string) {
    super(message);
    this.name = "AnchorRejectedError";
  }
}

async function connect() {
  const url = anchorRpcUrl();
  const transport = http(url, { timeout: 10_000, retryCount: 0 });
  let chainId: number;
  try {
    chainId = await createPublicClient({ transport }).getChainId();
  } catch {
    throw new ChainUnavailableError(`No local chain is answering at ${url}. Start one with npm run chain.`);
  }
  const chain = defineChain({
    id: chainId,
    name: "Local development chain",
    nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
    rpcUrls: { default: { http: [url] } },
  });
  return {
    url,
    chainId,
    publicClient: createPublicClient({ chain, transport, pollingInterval: 100 }),
    walletClient: createWalletClient({ chain, transport, pollingInterval: 100 }),
  };
}

type Connection = Awaited<ReturnType<typeof connect>>;

async function guard<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof HttpError) throw error;
    if (error instanceof BaseError) {
      const revert = error.walk((cause) => cause instanceof ContractFunctionRevertedError);
      if (revert instanceof ContractFunctionRevertedError) {
        throw new AnchorRejectedError(
          `The anchor contract refused the transaction: ${revert.data?.errorName ?? revert.shortMessage}`,
        );
      }
      if (error.walk((cause) => cause instanceof HttpRequestError || cause instanceof TimeoutError)) {
        throw new ChainUnavailableError(`The local chain at ${anchorRpcUrl()} stopped responding`);
      }
    }
    throw error;
  }
}

async function operator(connection: Connection): Promise<Address> {
  const [account] = await connection.walletClient.getAddresses();
  if (!account) {
    throw new ChainUnavailableError("The chain node exposes no unlocked development account to send anchors from");
  }
  return account;
}

/** Zeroes the immutable slots solc reports, so deployed code can be compared with the artifact. */
function maskImmutables(hex: string): string {
  const bytes = Buffer.from(hex.replace(/^0x/, ""), "hex");
  for (const ranges of Object.values(artifact.immutableReferences as Record<string, { start: number; length: number }[]>)) {
    for (const { start, length } of ranges) bytes.fill(0, start, start + length);
  }
  return bytes.toString("hex");
}

/** Whether code is the compiled contracts/OmniTrustAnchor.sol, ignoring its immutable owner. */
export function isAnchorContractCode(code: Hex | undefined): boolean {
  if (!code || code === "0x") return false;
  return maskImmutables(code) === maskImmutables(artifact.deployedBytecode);
}

export type ChainInfo = { rpcUrl: string; chainId: number; genesisHash: Hex; blockNumber: bigint };

export async function chainInfo(): Promise<ChainInfo> {
  const connection = await connect();
  return guard(async () => {
    const genesis = await connection.publicClient.getBlock({ blockNumber: 0n });
    return {
      rpcUrl: connection.url,
      chainId: connection.chainId,
      genesisHash: genesis.hash,
      blockNumber: await connection.publicClient.getBlockNumber(),
    };
  });
}

export async function deployAnchorContract() {
  const connection = await connect();
  return guard(async () => {
    const account = await operator(connection);
    const txHash = await connection.walletClient.deployContract({
      abi: ANCHOR_ABI,
      bytecode: `0x${artifact.bytecode}`,
      account,
    });
    const receipt = await connection.publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 30_000 });
    if (receipt.status !== "success" || !receipt.contractAddress) {
      throw new AnchorRejectedError("The anchor contract deployment transaction failed");
    }
    const genesis = await connection.publicClient.getBlock({ blockNumber: 0n });
    return {
      address: receipt.contractAddress,
      txHash,
      owner: account,
      chainId: connection.chainId,
      genesisHash: genesis.hash,
    };
  });
}

export async function contractCodeMatches(address: Address): Promise<boolean> {
  const connection = await connect();
  return guard(async () => isAnchorContractCode(await connection.publicClient.getCode({ address })));
}

export async function submitRoot(address: Address, root: Hex, leafCount: number) {
  const connection = await connect();
  return guard(async () => {
    const account = await operator(connection);
    // Simulate first, so a refusal is reported with the contract's own error name.
    const { request } = await connection.publicClient.simulateContract({
      address,
      abi: ANCHOR_ABI,
      functionName: "anchor",
      args: [root, leafCount],
      account,
    });
    const txHash = await connection.walletClient.writeContract(request);
    const receipt = await connection.publicClient.waitForTransactionReceipt({ hash: txHash, timeout: 30_000 });
    if (receipt.status !== "success") throw new AnchorRejectedError("The anchoring transaction reverted");
    const block = await connection.publicClient.getBlock({ blockNumber: receipt.blockNumber });
    return {
      txHash,
      blockNumber: receipt.blockNumber,
      blockTimestamp: new Date(Number(block.timestamp) * 1000),
    };
  });
}

export type OnChainAnchor = {
  codeMatches: boolean;
  anchoredAtBlock: bigint;
  event: { leafCount: number; blockNumber: bigint; timestamp: Date; txHash: Hex } | null;
};

export async function readAnchor(address: Address, root: Hex): Promise<OnChainAnchor> {
  const connection = await connect();
  return guard(async () => {
    const codeMatches = isAnchorContractCode(await connection.publicClient.getCode({ address }));
    if (!codeMatches) return { codeMatches, anchoredAtBlock: 0n, event: null };

    const anchoredAtBlock = (await connection.publicClient.readContract({
      address,
      abi: ANCHOR_ABI,
      functionName: "anchoredAtBlock",
      args: [root],
    })) as bigint;

    const events = await connection.publicClient.getContractEvents({
      address,
      abi: ANCHOR_ABI,
      eventName: "Anchored",
      args: { root } as never,
      fromBlock: 0n,
    });
    const first = events[0];
    const args = first?.args as { root: Hex; leafCount: number; blockNumber: bigint; timestamp: bigint } | undefined;

    return {
      codeMatches,
      anchoredAtBlock,
      event:
        first && args
          ? {
              leafCount: Number(args.leafCount),
              blockNumber: args.blockNumber,
              timestamp: new Date(Number(args.timestamp) * 1000),
              txHash: first.transactionHash,
            }
          : null,
    };
  });
}
