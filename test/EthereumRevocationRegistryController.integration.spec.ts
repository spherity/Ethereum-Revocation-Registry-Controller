import {createProvider, GetDateForTodayPlusDays, sleepForMs} from './testUtils'
import {RevocationRegistry, factories} from "@spherity/ethr-revocation-registry/types/ethers-v6";
import {
  EthereumRevocationRegistryController,
  RevocationKeyInstruction,
  RevocationKeyPath,
  RevocationListPath
} from "../src";
import {Wallet, keccak256, toUtf8Bytes} from "ethers";

jest.setTimeout(30000)

describe('EthrRevocationRegistryController', () => {
  let registry: RevocationRegistry
  let controller: EthereumRevocationRegistryController
  let typedDataSignableRegistry
  let typedDataSignableController: EthereumRevocationRegistryController
  let typedDataSigner: Wallet
  let secondTypedDataSignableRegistry
  let secondTypedDataSignableController: EthereumRevocationRegistryController
  let secondTypedDataSigner: Wallet
  let accounts: string[]
  const exampleList = "0x3458b9bfc7963978b7d40ef225177c45193c2889902357db3b043a4e319a9628"
  const exampleRevocationKey = "0x89343794d2fb7dd5d0fba9593a4bb13beaff93a61577029176d0117b0c53b8e6"

  function generateRevocationKeyPathForAccount(account: string): RevocationKeyPath {
    return {
      namespace: account,
      list: exampleList,
      revocationKey: exampleRevocationKey,
    }
  }

  function generateRevocationListPathForAccount(account: string): RevocationListPath {
    return {
      namespace: account,
      list: exampleList,
    }
  }

  const web3Provider = createProvider()

  beforeEach(async () => {
    const factory = new factories.RevocationRegistry__factory().connect(await web3Provider.getSigner(0))
    registry = await factory.deploy()
    const deploymentTx = await registry.deploymentTransaction();
    if(!deploymentTx) throw new Error("Couldn't fetch deployment TX for registry contract");
    await deploymentTx.wait();

    const accountProviders = await web3Provider.listAccounts();
    accounts = await Promise.all(accountProviders.map(async (account) => await account.getAddress()));

    const registryAddress = await registry.getAddress();

    controller = new EthereumRevocationRegistryController({contract: registry, provider: web3Provider, address: registryAddress})

    typedDataSigner = new Wallet("0x278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f", web3Provider)
    typedDataSignableRegistry = registry.connect(typedDataSigner)
    typedDataSignableController = new EthereumRevocationRegistryController({
      contract: typedDataSignableRegistry,
      provider: web3Provider,
      signer: typedDataSigner,
      address: registryAddress
    })

    secondTypedDataSigner = new Wallet("0x0000000000000000000000000000000000000000000000000000000000000005", web3Provider)
    secondTypedDataSignableRegistry = registry.connect(secondTypedDataSigner)
    secondTypedDataSignableController = new EthereumRevocationRegistryController({
      contract: secondTypedDataSignableRegistry,
      provider: web3Provider,
      signer: secondTypedDataSigner,
      address: registryAddress
    })
  })

  it('checks revocation status for default namespaces', async () => {
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[0]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[1]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[2]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[3]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[4]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[5]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[6]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[7]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[8]))).resolves.toEqual(false)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[9]))).resolves.toEqual(false)
  })

  it('revokes key and then unrevokes it', async () => {
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[0]))).resolves.toEqual(false)
    await controller.changeStatus(true, generateRevocationKeyPathForAccount(accounts[0]))
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[0]))).resolves.toEqual(true)
    await controller.changeStatus(false, generateRevocationKeyPathForAccount(accounts[0]))
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[0]))).resolves.toEqual(false)
  })

  it('revokes key, unrevokes & checks status in the past correctly', async () => {
    await controller.changeStatus(true, generateRevocationKeyPathForAccount(accounts[0]))
    await sleepForMs(1000)
    const revokedDate = new Date()
    await sleepForMs(1000)
    await controller.changeStatus(false, generateRevocationKeyPathForAccount(accounts[0]))
    await sleepForMs(1000)
    const unrevokedDate = new Date()
    await sleepForMs(1000)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[0]), {timestamp: revokedDate})).resolves.toEqual(true)
    await expect(controller.isRevoked(generateRevocationKeyPathForAccount(accounts[0]), {timestamp: unrevokedDate})).resolves.toEqual(false)
  })

  describe('ChangeStatusSigned', () => {
    it('Separate signer creates a signed payload for the initial controller to send out', async () => {
      const payload = await typedDataSignableController.generateChangeStatusSignedPayload(true, generateRevocationKeyPathForAccount(typedDataSigner.address))
      const transaction = await controller.changeStatusSigned(payload)
      expect(transaction.wait()).resolves
      await expect(controller.isRevoked(generateRevocationKeyPathForAccount(typedDataSigner.address))).resolves.toEqual(true)
    });

    it('Second execution of a signed Payload is aborted due to old nonce', async () => {
      const payload1 = await typedDataSignableController.generateChangeStatusSignedPayload(true, generateRevocationKeyPathForAccount(typedDataSigner.address))
      const transaction1 = await controller.changeStatusSigned(payload1)
      expect(transaction1.wait()).resolves

      const payload2 = await typedDataSignableController.generateChangeStatusSignedPayload(false, generateRevocationKeyPathForAccount(typedDataSigner.address))

      const transaction2 = await controller.changeStatusSigned(payload2)
      expect(transaction2.wait()).resolves

      expect(controller.changeStatusSigned(payload1)).rejects.toThrow(Error)
    });
  });

  describe('ChangeStatusDelegated', () => {
    it('Separate signer creates a signed payload for the initial controller to send out', async () => {
      const prepareTransaction = await typedDataSignableController.addListDelegate(generateRevocationListPathForAccount(typedDataSigner.address), secondTypedDataSigner.address, GetDateForTodayPlusDays(5))
      expect(prepareTransaction.wait()).resolves
      const payload = await secondTypedDataSignableController.generateChangeStatusDelegatedSignedPayload(true, generateRevocationKeyPathForAccount(typedDataSigner.address))
      const transaction = await controller.changeStatusDelegatedSigned(payload)
      expect(transaction.wait()).resolves
      await expect(controller.isRevoked(generateRevocationKeyPathForAccount(typedDataSigner.address))).resolves.toEqual(true)
    });
  });

  describe('ChangeStatusesInListSigned', () => {
    it('Separate signer creates a signed payload for the initial controller to send out', async () => {
      const revocationListPath = generateRevocationListPathForAccount(typedDataSigner.address)

      const revocationKeyInstructions: RevocationKeyInstruction[] = [
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey")),
          revoked: true
        } as any,
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
          revoked: true
        },
      ];

      const payload = await typedDataSignableController.generateChangeStatusesInListSignedPayload(generateRevocationListPathForAccount(typedDataSigner.address), revocationKeyInstructions)
      const transaction = await controller.changeStatusesInListSigned(payload)
      expect(transaction.wait()).resolves

      const expectedRevocationKeyPath = {
        namespace: revocationListPath.namespace,
        list: revocationListPath.list,
        revocationKey: revocationKeyInstructions[0].revocationKey
      } as RevocationKeyPath

      await expect(controller.isRevoked(expectedRevocationKeyPath)).resolves.toEqual(revocationKeyInstructions[0].revoked)
    });
  });

  describe('ChangeStatusesInListDelegatedSigned', () => {
    it('Separate signer creates a signed payload for the initial controller to send out', async () => {
      const revocationListPath = generateRevocationListPathForAccount(typedDataSigner.address)
      const prepareTransaction = await typedDataSignableController.addListDelegate(generateRevocationListPathForAccount(typedDataSigner.address), secondTypedDataSigner.address, GetDateForTodayPlusDays(5))
      expect(prepareTransaction.wait()).resolves

      const revocationKeyInstructions: RevocationKeyInstruction[] = [
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey")),
          revoked: true
        } as any,
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
          revoked: true
        },
      ];

      const payload = await secondTypedDataSignableController.generateChangeStatusesInListDelegatedSignedPayload(generateRevocationListPathForAccount(typedDataSigner.address), revocationKeyInstructions)
      const transaction = await controller.changeStatusesInListDelegatedSigned(payload)
      expect(transaction.wait()).resolves

      const expectedRevocationKeyPath = {
        namespace: revocationListPath.namespace,
        list: revocationListPath.list,
        revocationKey: revocationKeyInstructions[0].revocationKey
      } as RevocationKeyPath

      await expect(controller.isRevoked(expectedRevocationKeyPath)).resolves.toEqual(revocationKeyInstructions[0].revoked)
    });
  });

  describe('ChangeListStatusSigned', () => {
    it('Separate signer creates a signed payload for the initial controller to send out', async () => {
      const payload = await typedDataSignableController.generateChangeListStatusSignedPayload(true, generateRevocationListPathForAccount(typedDataSigner.address))
      const transaction = await controller.changeListStatusSigned(payload)
      expect(transaction.wait()).resolves
      await expect(controller.isRevoked(generateRevocationKeyPathForAccount(typedDataSigner.address))).resolves.toEqual(true)
    });
  });

  describe('ChangeListOwnerSigned', () => {
    it('Owner as a signer creates a meta transaction for changing the list owner and then expect the new owner to be able to write into the list while the past owner fails doing that', async () => {
      const revocationStatus = true
      const payload = await typedDataSignableController.generateChangeListOwnerSignedPayload(generateRevocationListPathForAccount(typedDataSigner.address), secondTypedDataSigner.address)
      const transaction = await controller.changeListOwnerSigned(payload)
      expect(transaction.wait()).resolves
      expect(registry.identityIsOwner(typedDataSigner.address, generateRevocationKeyPathForAccount(typedDataSigner.address).list, secondTypedDataSigner.address)).resolves.toEqual(true)
      const transaction2 = await secondTypedDataSignableController.changeStatus(revocationStatus, generateRevocationKeyPathForAccount(typedDataSigner.address))
      expect(transaction2.wait()).resolves
      expect(controller.isRevoked(generateRevocationKeyPathForAccount(typedDataSigner.address))).resolves.toEqual(revocationStatus)
      expect(secondTypedDataSignableController.changeStatus(revocationStatus, generateRevocationKeyPathForAccount(typedDataSigner.address))).rejects
    });
  });

  describe('AddListDelegateSigned', () => {
    it('Owner as a signer creates a meta transaction for adding a delegate and then the delegate should be able to write into the list', async () => {
      const revocationStatus = true
      const payload = await typedDataSignableController.generateAddListDelegateSignedPayload(generateRevocationListPathForAccount(typedDataSigner.address), secondTypedDataSigner.address, GetDateForTodayPlusDays(5))
      const transaction = await controller.addListDelegateSigned(payload)
      expect(transaction.wait()).resolves
      const transaction2 = await secondTypedDataSignableController.changeStatusDelegated(revocationStatus, generateRevocationKeyPathForAccount(typedDataSigner.address))
      expect(transaction2.wait()).resolves
      expect(controller.isRevoked(generateRevocationKeyPathForAccount(typedDataSigner.address))).resolves.toEqual(revocationStatus)
    });
  });

  describe('RemoveListDelegateSigned', () => {
    it('Owner as a signer creates a meta transaction for adding a delegate, removing it again and then expect that writing into the list with the delegate fails', async () => {
      const revocationStatus = true
      const payload = await typedDataSignableController.generateAddListDelegateSignedPayload(generateRevocationListPathForAccount(typedDataSigner.address), secondTypedDataSigner.address, GetDateForTodayPlusDays(5))
      const transaction = await controller.addListDelegateSigned(payload)
      expect(transaction.wait()).resolves
      const removalPayload = await typedDataSignableController.generateRemoveListDelegateSignedPayload(generateRevocationListPathForAccount(typedDataSigner.address), secondTypedDataSigner.address)
      const removalTransaction = await controller.removeListDelegateSigned(removalPayload)
      expect(removalTransaction.wait()).resolves
      expect(secondTypedDataSignableController.changeStatusDelegated(revocationStatus, generateRevocationKeyPathForAccount(typedDataSigner.address))).rejects.toThrow(Error)
    });
  });
})
