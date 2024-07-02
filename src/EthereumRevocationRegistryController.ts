/**
 * A class that can be used to interact with the EIP-5539 contract on behalf of a local controller key-pair
 */
import {factories, RevocationRegistry} from "@spherity/ethr-revocation-registry/types/ethers-v6";
import {Signer, Provider, JsonRpcProvider, ContractTransactionResponse, ContractRunner, TypedDataDomain, isHexString, Networkish, BlockTag, isAddress} from "ethers";
import {RevocationListPath} from "./types/RevocationListPath";
import {RevocationKeyInstruction} from "./types/RevocationKeyInstruction";
import {RevocationKeyPath} from "./types/RevocationKeyPath";
import {isEmpty} from "lodash";
import {TypedContractEvent, TypedEventLog} from "@spherity/ethr-revocation-registry/types/ethers-v6/common";
import {
  EIP712AddListDelegateType,
  EIP712ChangeListOwnerType,
  EIP712ChangeListStatusType,
  EIP712ChangeStatusDelegatedType,
  EIP712ChangeStatusesInListDelegatedType,
  EIP712ChangeStatusesInListType,
  EIP712ChangeStatusType, EIP712DomainName,
  EIP712RemoveListDelegateType,
  getRevocationRegistryDeploymentAddress
} from "@spherity/ethr-revocation-registry";
import {RevocationKeysAndStatuses} from "./types/RevocationKeysAndStatuses";
const DEFAULT_REGISTRY_CHAIN_ID = 1

type TimestampedEvent<T extends TypedContractEvent> = T & {
  timestamp: number
}

export type Signaturish =  {
  signer: string
  signature: string
  nonce: number
}

export type ChangeStatusSignedOperation = Signaturish & {
  revoked: boolean
  revocationKeyPath: RevocationKeyPath
}

export type ChangeStatusesInListSignedOperation = Signaturish & {
  revocationListPath: RevocationListPath,
  revocationKeyInstructions: RevocationKeyInstruction[]
}

export type ChangeListOwnerSignedOperation = Signaturish & {
  revocationListPath: RevocationListPath,
  newOwner: string,
}

export type AddListDelegateSignedOperation = Signaturish & {
  revocationListPath: RevocationListPath,
  delegate: string
  expiryDate: Date
}

export type RemoveListDelegateSignedOperation = Signaturish & {
  revocationListPath: RevocationListPath,
  delegate: string
}

export type ChangeListStatusSignedOperation = Signaturish & {
  revoked: boolean,
  revocationListPath: RevocationListPath
}

export interface EthereumRevocationRegistryControllerConfig {
  contract?: RevocationRegistry,
  provider?: Provider,
  signer?: Signer,
  rpcUrl?: string,
  network?: Networkish,
  address?: string;
  chainId?: number;
}

export interface IsRevokedOptions {
  timestamp?: Date,
  blockTag?: BlockTag
}

const isSigner = (contractRunner: ContractRunner): contractRunner is Signer => {
  return (contractRunner as Signer).getAddress !== undefined;
}

export class EthereumRevocationRegistryController {
  private registry: RevocationRegistry
  private typedDataDomain: TypedDataDomain | undefined

  constructor(config: EthereumRevocationRegistryControllerConfig) {
    const chainId = config.chainId !== undefined ? config.chainId : DEFAULT_REGISTRY_CHAIN_ID
    const address = config.address !== undefined
      ? config.address
      : getRevocationRegistryDeploymentAddress(chainId)

    if (config.contract) {
      this.registry = config.contract
    } else if(config.signer && config.signer.provider) {
      this.registry = factories.RevocationRegistry__factory
        .connect(address, config.signer)
    } else if(config.provider && !config.signer) {
      this.registry = factories.RevocationRegistry__factory
        .connect(address,{provider: config.provider})
    } else if(config.rpcUrl && config.signer && config.network) {
      const provider = new JsonRpcProvider(config.rpcUrl, config.network)
      const attachedSigner = config.signer.connect(provider)
      this.registry = factories.RevocationRegistry__factory
        .connect(address, attachedSigner)
    } else if(config.rpcUrl && !config.signer && config.network) {
      const provider = new JsonRpcProvider(config.rpcUrl, config.network)
      this.registry = factories.RevocationRegistry__factory
        .connect(address, {provider: provider})
    } else {
      throw new Error("Either a contract instance, a provider with optional signer or a RPCUrl with a network with optional signer must be provided")
    }
  }

  private async getEip712Domain(): Promise<TypedDataDomain> {
    const version = await this.registry.version()
    if(!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if(!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    const network = await this.registry.runner.provider.getNetwork();
    const chainId = network.chainId;

    return {
      name: EIP712DomainName,
      version: version,
      chainId: Number(chainId),
      verifyingContract: await this.registry.getAddress()
    } as TypedDataDomain
  }

  public async getSignerAddress(): Promise<string> {
    if(!this.registry.runner) {
      throw new Error("Controller has no runner!")
    }
    // TODO: improve this?
    if('getAddress' in this.registry.runner) {
      throw new Error("Controller has no runner!")
    }
    return (this.registry.runner as Signer).getAddress()
  }

  private validateSignaturish(signaturish: Signaturish) {
    this.validateAddress(signaturish.signer)
    this.validateSignature(signaturish.signature)
    if(signaturish.nonce === null) throw new Error("Nonce must be set")
  }

  private validateSignature(signature: string) {
    if(!isHexString(signature)) {
      throw new Error(`Supplied signature '${signature}' is not valid (notice: must start with 0x prefix; must contain only HEX character set)`)
    }
  }

  private validateAddress(address: string) {
    if(!isAddress(address)) {
      throw new Error(`Supplied address '${address}' is not valid (notice: must start with 0x prefix; must contain only HEX character set; must have a length of 42)`)
    }
  }

  private validateBytes32(bytes32String: string) {
    if(!isHexString(bytes32String)) {
      throw new Error(`Supplied bytes32 string '${bytes32String}' is not valid (notice: must start with 0x prefix; must contain only HEX character set)`)
    }
    if(bytes32String.length !== 66) {
      throw new Error(`Supplied bytes32 string '${bytes32String}' has wrong length of '${bytes32String.length}' instead of '66'.`)
    }
  }

  private validateRevocationListPath(revocationListPath: RevocationListPath) {
    if(!revocationListPath) {
      throw new Error(`revocationListPath must not be null`)
    }
    if(isEmpty(revocationListPath.namespace)) {
      throw new Error(`namespace in revocationListPath must not be null`)
    }
    if(isEmpty(revocationListPath.list)) {
      throw new Error(`list in revocationListPath must not be null`)
    }

    this.validateAddress(revocationListPath.namespace);
    this.validateBytes32(revocationListPath.list);
  }

  private validateRevocationKeyPath(revocationKeyPath: RevocationKeyPath) {
    if(isEmpty(revocationKeyPath.revocationKey)) {
      throw new Error(`revocationKey in revocationKeyPath must not be null`)
    }
    this.validateRevocationListPath(revocationKeyPath)
    this.validateBytes32(revocationKeyPath.revocationKey);
  }

  private validateExpiryDateIsInFuture(expiryDate: Date) {
    const today = new Date(Date.now())
    if(expiryDate < today) {
      throw new Error("expiryDate must be in the future")
    }
  }

  private async checkNonceForAddress(address: string, expectedNonce: number) {
    const currentNonce = await this.registry.nonces(address)
    if(Number(currentNonce) !== expectedNonce) {
      throw new Error(`Nonce in the payload is out of date or invalid (Expected: '${expectedNonce}' ; Current: '${currentNonce}').`)
    }
  }

  private async getTimestampedEventsUntilDate<T extends TypedContractEvent>(events: Array<TypedEventLog<T>>, timestamp: Date) {
    const timestampSeconds = Math.floor(timestamp.getTime()/1000);
    const blocks = await Promise.all(events.map((event) => {
      return event.getBlock();
    }));

    let timestampedEvents = blocks.map((block, index) => {
      if(block.timestamp <= timestampSeconds) {
        return {...events[index], ...{timestamp: block.timestamp}};
      }
    });

    // THIS IS THE GIGA HACK JUST TO REMOVE THE POSSIBLE UNDEFINED FROM THE ARRAY
    // THAT IS INTRODUCED BY THE .MAP ABOVE
    type timestampedEvent = Exclude<typeof timestampedEvents[0], undefined>;

    // remove unwanted undefined entries in array due to map usage
    timestampedEvents = timestampedEvents.filter(item => item !== undefined);
    return this.sortByDateDescending(timestampedEvents as Array<timestampedEvent>);
  }

  private sortByDateDescending<T extends { timestamp: number }>(events: Array<T>) {
    return events.sort(
        (eventA, eventB) => Number(eventB.timestamp) - Number(eventA.timestamp),
    )
  }

  private async getKeyRevocationStateAtDate(revocationKeyPath: RevocationKeyPath, timestamp: Date): Promise<boolean> {
    let queryFilterReturnValues;
    try {
      queryFilterReturnValues = await Promise.all([
        this.registry.queryFilter(this.registry.filters.RevocationListStatusChanged(revocationKeyPath.namespace, revocationKeyPath.list)),
        this.registry.queryFilter(this.registry.filters.RevocationStatusChanged(revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey)),
      ]);
    } catch(error) {
      throw new Error("Cannot fetch revocation state due error fetching events of contract: " + error)
    }

    const timestampedListStatusChangedEvents = await this.getTimestampedEventsUntilDate(queryFilterReturnValues[0], timestamp);
    const timestampedRevocationStatusChangedEvents = await this.getTimestampedEventsUntilDate(queryFilterReturnValues[1], timestamp);

    if(timestampedListStatusChangedEvents.length > 0) {
      return timestampedListStatusChangedEvents[0].args.revoked === true || timestampedRevocationStatusChangedEvents[0].args.revoked === true;
    }
    if(timestampedRevocationStatusChangedEvents.length > 0) {
      return timestampedRevocationStatusChangedEvents[0].args.revoked;
    }
    return false
  }

  async isRevoked(revocationKeyPath: RevocationKeyPath, options?: IsRevokedOptions): Promise<boolean> {
    this.validateRevocationKeyPath(revocationKeyPath);
    if(options && options.timestamp) {
      return this.getKeyRevocationStateAtDate(revocationKeyPath, options.timestamp);
    } else {
      let blockTag = options && options.blockTag ? options.blockTag : "latest"
      const result = await this.registry.isRevoked(revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey, {blockTag: blockTag});
      if(result === undefined) {
        throw new Error(`Revocation couldn't be fetched for ${blockTag}`)
      }
      return result;
    }
  }

  async changeStatus(revoked: boolean, revocationKeyPath: RevocationKeyPath): Promise<ContractTransactionResponse> {
    if(revoked === undefined) throw new Error("revoked must be set")
    this.validateRevocationKeyPath(revocationKeyPath)
    return this.registry.changeStatus(revoked, revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey)
  }

  private async _changeStatusSigned(signedOperation: ChangeStatusSignedOperation, delegatedCall: boolean = false): Promise<ContractTransactionResponse> {
    if(signedOperation.revoked === undefined) throw new Error("revoked must be set")
    this.validateSignaturish(signedOperation)
    this.validateRevocationKeyPath(signedOperation.revocationKeyPath)
    await this.checkNonceForAddress(signedOperation.signer, signedOperation.nonce)
    const revocationKeyPath = signedOperation.revocationKeyPath
    if(delegatedCall) {
      return this.registry.changeStatusDelegatedSigned(
          signedOperation.revoked,
          revocationKeyPath.namespace,
          revocationKeyPath.list,
          revocationKeyPath.revocationKey,
          signedOperation.signer,
          signedOperation.signature,
      )
    } else {
      return this.registry.changeStatusSigned(
          signedOperation.revoked,
          revocationKeyPath.namespace,
          revocationKeyPath.list,
          revocationKeyPath.revocationKey,
          signedOperation.signer,
          signedOperation.signature,
      )
    }
  }

  async changeStatusSigned(signedOperation: ChangeStatusSignedOperation): Promise<ContractTransactionResponse> {
    return this._changeStatusSigned(signedOperation)
  }

  private async _generateChangeStatusSignedPayload(revoked: boolean, revocationKeyPath: RevocationKeyPath, delegatedCall: boolean = false): Promise<ChangeStatusSignedOperation> {
    if (!this.typedDataDomain) {
      this.typedDataDomain = await this.getEip712Domain()
    }
    if (!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if (!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    if (!isSigner(this.registry.runner)) throw new Error("Please provide a signer in the constructor as it is required for the method to work!")
    this.validateRevocationKeyPath(revocationKeyPath)
    const signer = await this.registry.runner.getAddress()
    const nonce = await this.registry.nonces(signer)

    const values = {
      revoked: revoked,
      namespace: revocationKeyPath.namespace,
      revocationList: revocationKeyPath.list,
      revocationKey: revocationKeyPath.revocationKey,
      signer: signer,
      nonce: Number(nonce)
    }

    let signature: string
    if(delegatedCall) {
      signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712ChangeStatusDelegatedType, values)
    } else {
      signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712ChangeStatusType, values)
    }

    return {
      revoked: revoked,
      revocationKeyPath: revocationKeyPath,
      signer: signer,
      signature: signature,
      nonce: Number(nonce)
    } as ChangeStatusSignedOperation
  }

  async generateChangeStatusSignedPayload(revoked: boolean, revocationKeyPath: RevocationKeyPath): Promise<ChangeStatusSignedOperation> {
    return this._generateChangeStatusSignedPayload(revoked, revocationKeyPath)
  }

  async changeStatusDelegated(revoked: boolean, revocationKeyPath: RevocationKeyPath): Promise<ContractTransactionResponse> {
    this.validateRevocationKeyPath(revocationKeyPath);
    return this.registry.changeStatusDelegated(revoked, revocationKeyPath.namespace,  revocationKeyPath.list, revocationKeyPath.revocationKey);
  }

  async changeStatusDelegatedSigned(signedOperation: ChangeStatusSignedOperation): Promise<ContractTransactionResponse> {
    return this._changeStatusSigned(signedOperation, true)
  }

  async generateChangeStatusDelegatedSignedPayload(revoked: boolean, revocationKeyPath: RevocationKeyPath): Promise<ChangeStatusSignedOperation> {
    return this._generateChangeStatusSignedPayload(revoked, revocationKeyPath, true)
  }

  private convertRevocationKeyInstructions(revocationKeyInstructions: RevocationKeyInstruction[]): RevocationKeysAndStatuses {
    let revocationKeys: string[] = [];
    let revokedStatuses: boolean[] = [];
    revocationKeyInstructions.forEach((revocationKeyInstruction) => {
      if(!revocationKeyInstruction.revocationKey) {
        throw new Error(`revocationKey in RevocationKeyInstruction must not be null!`)
      }
      if(revocationKeyInstruction.revoked === undefined) {
        throw new Error(`revoked in RevocationKeyInstruction must not be null!`)
      }
      this.validateBytes32(revocationKeyInstruction.revocationKey);
      revocationKeys.push(revocationKeyInstruction.revocationKey);
      revokedStatuses.push(revocationKeyInstruction.revoked);
    })

    return {
      revocationKeys: revocationKeys,
      revokedStatuses: revokedStatuses
    }
  }

  private async _changeStatusesInList(revocationListPath: RevocationListPath, revocationKeyInstructions: RevocationKeyInstruction[], delegatedCall: boolean = false): Promise<ContractTransactionResponse> {
    this.validateRevocationListPath(revocationListPath);
    const keysAndStatuses: RevocationKeysAndStatuses = this.convertRevocationKeyInstructions(revocationKeyInstructions)

    if(delegatedCall) {
      return this.registry.changeStatusesInListDelegated(keysAndStatuses.revokedStatuses, revocationListPath.namespace, revocationListPath.list, keysAndStatuses.revocationKeys);
    } else {
      return this.registry.changeStatusesInList(keysAndStatuses.revokedStatuses, revocationListPath.namespace, revocationListPath.list, keysAndStatuses.revocationKeys);
    }
  }

  async changeStatusesInList(revocationListPath: RevocationListPath, revocationKeyInstructions: RevocationKeyInstruction[]): Promise<ContractTransactionResponse> {
    return this._changeStatusesInList(revocationListPath, revocationKeyInstructions)
  }

  async _changeStatusesInListSigned(signedOperation: ChangeStatusesInListSignedOperation, delegatedCall: boolean = false): Promise<ContractTransactionResponse> {
    if(signedOperation.revocationKeyInstructions === undefined) throw new Error("revocationKeyInstructions must be set")
    this.validateSignaturish(signedOperation)
    this.validateRevocationListPath(signedOperation.revocationListPath)
    await this.checkNonceForAddress(signedOperation.signer, signedOperation.nonce)
    const revocationListPath = signedOperation.revocationListPath

    const keysAndStatuses: RevocationKeysAndStatuses = this.convertRevocationKeyInstructions(signedOperation.revocationKeyInstructions)

    if(delegatedCall) {
      return this.registry.changeStatusesInListDelegatedSigned(
          keysAndStatuses.revokedStatuses,
          revocationListPath.namespace,
          revocationListPath.list,
          keysAndStatuses.revocationKeys,
          signedOperation.signer,
          signedOperation.signature,
      )
    } else {
      return this.registry.changeStatusesInListSigned(
          keysAndStatuses.revokedStatuses,
          revocationListPath.namespace,
          revocationListPath.list,
          keysAndStatuses.revocationKeys,
          signedOperation.signer,
          signedOperation.signature,
      )
    }
  }

  async changeStatusesInListSigned(signedOperation: ChangeStatusesInListSignedOperation): Promise<ContractTransactionResponse> {
    return this._changeStatusesInListSigned(signedOperation)
  }

  async generateChangeStatusesInListSignedPayload(revocationListPath: RevocationListPath, revocationKeyInstructions: RevocationKeyInstruction[]): Promise<ChangeStatusesInListSignedOperation> {
    return this._generateChangeStatusesInListSignedPayload(revocationListPath, revocationKeyInstructions)
  }

  async changeStatusesInListDelegated(revocationListPath: RevocationListPath, revocationKeyInstructions: RevocationKeyInstruction[]): Promise<ContractTransactionResponse> {
    return this._changeStatusesInList(revocationListPath, revocationKeyInstructions, true)
  }

  async changeStatusesInListDelegatedSigned(signedOperation: ChangeStatusesInListSignedOperation): Promise<ContractTransactionResponse> {
    return this._changeStatusesInListSigned(signedOperation, true)
  }

  async generateChangeStatusesInListDelegatedSignedPayload(revocationListPath: RevocationListPath, revocationKeyInstructions: RevocationKeyInstruction[]): Promise<ChangeStatusesInListSignedOperation> {
    return this._generateChangeStatusesInListSignedPayload(revocationListPath, revocationKeyInstructions, true)
  }

  private async _generateChangeStatusesInListSignedPayload(revocationListPath: RevocationListPath, revocationKeyInstructions: RevocationKeyInstruction[], delegatedCall: boolean = false): Promise<ChangeStatusesInListSignedOperation> {
    if(!this.typedDataDomain) {
      this.typedDataDomain = await this.getEip712Domain()
    }

    if(!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if(!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    if(!isSigner(this.registry.runner)) throw new Error("Please provide a signer in the constructor as it is required for the method to work!")
    this.validateRevocationListPath(revocationListPath)
    const signer = await this.registry.runner.getAddress()
    const nonce = await this.registry.nonces(signer)

    const keysAndStatuses: RevocationKeysAndStatuses = this.convertRevocationKeyInstructions(revocationKeyInstructions)

    const values = {
      revoked: keysAndStatuses.revokedStatuses,
      namespace: revocationListPath.namespace,
      revocationList: revocationListPath.list,
      revocationKeys: keysAndStatuses.revocationKeys,
      signer: signer,
      nonce: Number(nonce)
    }

    let signature: string
    if(delegatedCall) {
      signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712ChangeStatusesInListDelegatedType, values)
    } else {
      signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712ChangeStatusesInListType, values)
    }

    return {
      revocationListPath: revocationListPath,
      revocationKeyInstructions: revocationKeyInstructions,
      signer: signer,
      signature: signature,
      nonce: Number(nonce)
    } as ChangeStatusesInListSignedOperation
  }

  async changeListOwner(revocationListPath: RevocationListPath, newOwner: string): Promise<ContractTransactionResponse> {
    this.validateRevocationListPath(revocationListPath);
    this.validateAddress(newOwner);
    return this.registry.changeListOwner(revocationListPath.namespace, newOwner, revocationListPath.list);
  }

  async changeListOwnerSigned(signedOperation: ChangeListOwnerSignedOperation): Promise<ContractTransactionResponse> {
    const revocationListPath = signedOperation.revocationListPath
    this.validateRevocationListPath(revocationListPath);
    this.validateAddress(signedOperation.newOwner);
    await this.checkNonceForAddress(signedOperation.signer, signedOperation.nonce)
    // TODO: ARGUMENT ORDER OF WILL CHANGE 'changeListOwnerSigned'
    return this.registry.changeListOwnerSigned(
        revocationListPath.namespace,
        signedOperation.newOwner,
        revocationListPath.list,
        signedOperation.signer,
        signedOperation.signature
    );
  }

  async generateChangeListOwnerSignedPayload(revocationListPath: RevocationListPath, newOwner: string): Promise<ChangeListOwnerSignedOperation> {
    if(!this.typedDataDomain) {
      this.typedDataDomain = await this.getEip712Domain()
    }

    if(!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if(!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    if(!isSigner(this.registry.runner)) throw new Error("Please provide a signer in the constructor as it is required for the method to work!")
    this.validateRevocationListPath(revocationListPath)
    this.validateAddress(newOwner)
    const signer = await this.registry.runner.getAddress()
    const nonce = await this.registry.nonces(signer)

    const values = {
      namespace: revocationListPath.namespace,
      newOwner: newOwner,
      revocationList: revocationListPath.list,
      signer: signer,
      nonce: Number(nonce)
    }

    const signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712ChangeListOwnerType, values)

    return {
      revocationListPath: revocationListPath,
      newOwner: newOwner,
      signer: signer,
      signature: signature,
      nonce: Number(nonce)
    } as ChangeListOwnerSignedOperation
  }

  async addListDelegate(revocationListPath: RevocationListPath, delegate: string, expiryDate: Date): Promise<ContractTransactionResponse> {
    this.validateRevocationListPath(revocationListPath);
    this.validateAddress(delegate);
    this.validateExpiryDateIsInFuture(expiryDate)
    const expiryDateEpochSeconds = Math.floor(expiryDate.getTime() / 1000);

    return this.registry.addListDelegate(revocationListPath.namespace, delegate, revocationListPath.list, expiryDateEpochSeconds);
  }

  async addListDelegateSigned(signedOperation: AddListDelegateSignedOperation): Promise<ContractTransactionResponse> {
    const revocationListPath = signedOperation.revocationListPath
    this.validateRevocationListPath(revocationListPath);
    this.validateAddress(signedOperation.delegate);
    await this.checkNonceForAddress(signedOperation.signer, signedOperation.nonce)
    if(!signedOperation.expiryDate) {
      throw new Error("expiryDate must not be null")
    }
    this.validateExpiryDateIsInFuture(signedOperation.expiryDate)
    const expiryDateEpochSeconds = Math.floor(signedOperation.expiryDate.getTime() / 1000);

    return this.registry.addListDelegate(
        revocationListPath.namespace,
        signedOperation.delegate,
        revocationListPath.list,
        expiryDateEpochSeconds
    );
  }

  async generateAddListDelegateSignedPayload(revocationListPath: RevocationListPath, delegate: string, expiryDate: Date): Promise<AddListDelegateSignedOperation> {
    if(!this.typedDataDomain) {
      this.typedDataDomain = await this.getEip712Domain()
    }
    if(!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if(!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    if(!isSigner(this.registry.runner)) throw new Error("Please provide a signer in the constructor as it is required for the method to work!")
    this.validateRevocationListPath(revocationListPath)
    this.validateAddress(delegate)
    this.validateExpiryDateIsInFuture(expiryDate)
    const expiryDateEpochSeconds = Math.floor(expiryDate.getTime() / 1000);
    const signer = await this.registry.runner.getAddress()
    const nonce = await this.registry.nonces(signer)

    const values = {
      namespace: revocationListPath.namespace,
      delegate: delegate,
      revocationList: revocationListPath.list,
      validity: expiryDateEpochSeconds,
      signer: signer,
      nonce: Number(nonce)
    }

    const signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712AddListDelegateType, values)

    return {
      revocationListPath: revocationListPath,
      delegate: delegate,
      expiryDate: expiryDate,
      signer: signer,
      signature: signature,
      nonce: Number(nonce)
    } as AddListDelegateSignedOperation
  }

  async removeListDelegate(revocationListPath: RevocationListPath, delegate: string): Promise<ContractTransactionResponse> {
    this.validateRevocationListPath(revocationListPath);
    this.validateAddress(delegate);

    return this.registry.removeListDelegate(revocationListPath.namespace, delegate, revocationListPath.list);
  }

  async removeListDelegateSigned(signedOperation: RemoveListDelegateSignedOperation): Promise<ContractTransactionResponse> {
    const revocationListPath = signedOperation.revocationListPath
    this.validateRevocationListPath(revocationListPath);
    this.validateAddress(signedOperation.delegate);
    await this.checkNonceForAddress(signedOperation.signer, signedOperation.nonce)

    return this.registry.removeListDelegate(revocationListPath.namespace, signedOperation.delegate, revocationListPath.list);
  }

  async generateRemoveListDelegateSignedPayload(revocationListPath: RevocationListPath, delegate: string): Promise<RemoveListDelegateSignedOperation> {
    if(!this.typedDataDomain) {
      this.typedDataDomain = await this.getEip712Domain()
    }
    if(!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if(!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    if(!isSigner(this.registry.runner)) throw new Error("Please provide a signer in the constructor as it is required for the method to work!")
    this.validateRevocationListPath(revocationListPath)
    this.validateAddress(delegate)
    const signer = await this.registry.runner.getAddress()
    const nonce = await this.registry.nonces(signer)

    const values = {
      namespace: revocationListPath.namespace,
      delegate: delegate,
      revocationList: revocationListPath.list,
      signer: signer,
      nonce: Number(nonce)
    }

    const signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712RemoveListDelegateType, values)

    return {
      revocationListPath: revocationListPath,
      delegate: delegate,
      signer: signer,
      signature: signature,
      nonce: Number(nonce)
    } as RemoveListDelegateSignedOperation
  }

  async changeListStatus(revoked: boolean, revocationListPath: RevocationListPath): Promise<ContractTransactionResponse> {
    if(revoked === undefined) throw new Error("revoked must be set")
    this.validateRevocationListPath(revocationListPath)
    return this.registry.changeListStatus(revoked, revocationListPath.namespace, revocationListPath.list)
  }

  async changeListStatusSigned(signedOperation: ChangeListStatusSignedOperation): Promise<ContractTransactionResponse> {
    if(signedOperation.revoked === undefined) throw new Error("revoked must be set")
    const revocationListPath = signedOperation.revocationListPath
    this.validateRevocationListPath(revocationListPath)
    await this.checkNonceForAddress(signedOperation.signer, signedOperation.nonce)

    return this.registry.changeListStatusSigned(
        signedOperation.revoked,
        revocationListPath.namespace,
        revocationListPath.list,
        signedOperation.signer,
        signedOperation.signature
    )
  }

  async generateChangeListStatusSignedPayload(revoked: boolean, revocationListPath: RevocationListPath): Promise<ChangeListStatusSignedOperation> {
    if(!this.typedDataDomain) {
      this.typedDataDomain = await this.getEip712Domain()
    }
    if(!this.registry.runner) throw new Error("Initialized without a contract runner.")
    if(!this.registry.runner.provider) throw new Error("Initialized without a provider.")
    if(!isSigner(this.registry.runner)) throw new Error("Please provide a signer in the constructor as it is required for the method to work!")
    this.validateRevocationListPath(revocationListPath)
    const signer = await this.registry.runner.getAddress()
    const nonce = await this.registry.nonces(signer)

    const values = {
      revoked: revoked,
      namespace: revocationListPath.namespace,
      revocationList: revocationListPath.list,
      signer: signer,
      nonce: Number(nonce)
    }

    const signature = await this.registry.runner.signTypedData(this.typedDataDomain, EIP712ChangeListStatusType, values)

    return {
      revoked: revoked,
      revocationListPath: revocationListPath,
      signer: signer,
      signature: signature,
      nonce: Number(nonce)
    } as ChangeListStatusSignedOperation
  }

}