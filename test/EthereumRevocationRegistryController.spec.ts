import {RevocationRegistry} from "@spherity/ethr-revocation-registry/types/ethers-v6";
import {
  EthereumRevocationRegistryController,
  RevocationKeyInstruction,
  RevocationKeyPath,
  RevocationListPath
} from "../src";
import {GetDateForTodayPlusDays} from "./testUtils";
import {when} from 'jest-when'
import {Block, ContractRunner, Network, Provider, Signer, keccak256, toUtf8Bytes} from "ethers";
import {EIP712DomainName} from "@spherity/ethr-revocation-registry";
import {ChangeStatusSignedOperation} from "../src/EthereumRevocationRegistryController";

jest.setTimeout(30000)

const validAddress = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
describe('EthrRevocationRegistryController', () => {
  let registry: EthereumRevocationRegistryController;
  let registryWithoutSigner: EthereumRevocationRegistryController;
  const networkMock = {
    chainId: 1,
    name: "Mocked Network",
  } as any as Network
  let signerMock = {
    getAddress: jest.fn(),
    signTypedData: jest.fn()
  } as unknown as Signer;
  const addressMock = "mockedRegistryAddress"
  let runnerMock = {}
  const contractVersion = "1.0.0"
  const registryContractMockWithoutRunner = {
    getAddress: jest.fn().mockResolvedValue(addressMock),
    isRevoked: jest.fn(),
    changeStatus: jest.fn(),
    changeStatusSigned: jest.fn(),
    changeStatusDelegated: jest.fn(),
    changeStatusesInList: jest.fn(),
    changeStatusesInListDelegated: jest.fn(),
    changeListOwner: jest.fn(),
    addListDelegate: jest.fn(),
    removeListDelegate: jest.fn(),
    changeListStatus: jest.fn(),
    queryFilter: jest.fn(),
    filters: {
      RevocationListStatusChanged: jest.fn(),
      RevocationStatusChanged: jest.fn(),
    },
    nonces: jest.fn(),
    version: jest.fn(),
  } as unknown as RevocationRegistry

  const registryContractMock = {
    ...registryContractMockWithoutRunner,
    runner: {
      ...signerMock,
      provider: {
        getNetwork: jest.fn(),
      } as any as Provider
    } as ContractRunner
  } as RevocationRegistry

  const registryContractMockWithOnlyProvider = {
    ...registryContractMockWithoutRunner,
    runner: {
      // BY DEFAULT THE RUNNER IS NOT A SIGNER
      // DEPENDS ON SETTING THE RUNNER CORRECTLY IN THE SPECIFIC TESTS
      provider: {
        getNetwork: jest.fn(),
      } as any as Provider
    } as ContractRunner
  } as RevocationRegistry

  const providerMock = {} as unknown as Provider

  beforeAll(async () => {
    registry = new EthereumRevocationRegistryController({
      contract: registryContractMock,
      provider: providerMock,
      signer: signerMock,
      address: addressMock
    });
    registryWithoutSigner = new EthereumRevocationRegistryController({
      contract: registryContractMockWithOnlyProvider,
      provider: providerMock,
      address: addressMock
    });
  })

  beforeEach(async () => {
    when(registryContractMock.runner!.provider!.getNetwork).mockResolvedValue(networkMock)
    when(registryContractMock.version).mockResolvedValue(contractVersion)
    when(signerMock.getAddress).mockResolvedValue(validAddress)
  })

  afterEach(async () => {
    jest.resetAllMocks();
  })

  describe('isRevoked', () => {
    it('should work with default "latest" blockTag directly calling the contract', async () => {
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }
      when(registryContractMock.isRevoked).calledWith(
          expect.anything(),
          expect.anything(),
          expect.anything(),
          expect.objectContaining({blockTag: "latest"})
      ).mockResolvedValue(false)

      expect(registry.isRevoked(revocationKeyPath)).resolves.toEqual(false);
      expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(1);
      expect(registryContractMock.queryFilter).toHaveBeenCalledTimes(0);
      expect(registryContractMock.isRevoked).toHaveBeenCalledWith(revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey, expect.objectContaining({blockTag: "latest"}));
    })

    it('should throw an error with invalid blockTag', async () => {
      const blockTag = 123123213213212131312
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }

      when(registryContractMock.isRevoked).calledWith(
          expect.anything(),
          expect.anything(),
          expect.anything(),
          expect.objectContaining({blockTag: blockTag})
      ).mockResolvedValue(undefined as any)

      expect(registry.isRevoked(revocationKeyPath, {blockTag: blockTag})).rejects.toThrow(Error);
      expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(1);
      expect(registryContractMock.queryFilter).toHaveBeenCalledTimes(0);
      expect(registryContractMock.isRevoked).toHaveBeenCalledWith(revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey, expect.objectContaining({blockTag: blockTag}));
    })

    describe('with timestamp', () => {
      it('should return a revoked state if the whole list is revoked even if the key is unrevoked', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }

        const timestamp = GetDateForTodayPlusDays(-5);

        when(registryContractMock.filters.RevocationListStatusChanged).mockReturnValue("mockedListStatusIdentifier" as any)
        when(registryContractMock.filters.RevocationStatusChanged).mockReturnValue("mockedKeyStatusIdentifier" as any)

        const typedListStatusEvent = {
          getBlock: jest.fn().mockResolvedValue({
            timestamp: Math.floor(GetDateForTodayPlusDays(-6).getTime()/1000)
          } as Block),
          args: {
            revoked: true
          }
        } as any

        const typedRevocationStatusEvent = {
          getBlock: jest.fn().mockResolvedValue({
            timestamp: Math.floor(GetDateForTodayPlusDays(-6).getTime()/1000)
          } as Block),
          args: {
            revoked: false
          }
        } as any

        when(registryContractMock.queryFilter).calledWith("mockedListStatusIdentifier" as any).mockResolvedValue([typedListStatusEvent]);
        when(registryContractMock.queryFilter).calledWith("mockedKeyStatusIdentifier" as any).mockResolvedValue([typedRevocationStatusEvent]);

        expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        expect(registry.isRevoked(revocationKeyPath, {timestamp: timestamp})).resolves.toEqual(true)
      })
      it('should return a revoked state if the whole list is unrevoked, but the key is revoked', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }

        const timestamp = GetDateForTodayPlusDays(-5);

        when(registryContractMock.filters.RevocationListStatusChanged).mockReturnValue("mockedListStatusIdentifier" as any)
        when(registryContractMock.filters.RevocationStatusChanged).mockReturnValue("mockedKeyStatusIdentifier" as any)

        const typedListStatusEvent = {
          getBlock: jest.fn().mockResolvedValue({
            timestamp: Math.floor(GetDateForTodayPlusDays(-6).getTime()/1000)
          } as Block),
          args: {
            revoked: false
          }
        } as any

        const typedRevocationStatusEvent = {
          getBlock: jest.fn().mockResolvedValue({
            timestamp: Math.floor(GetDateForTodayPlusDays(-6).getTime()/1000)
          } as Block),
          args: {
            revoked: true
          }
        } as any

        when(registryContractMock.queryFilter).calledWith("mockedListStatusIdentifier" as any).mockResolvedValue([typedListStatusEvent]);
        when(registryContractMock.queryFilter).calledWith("mockedKeyStatusIdentifier" as any).mockResolvedValue([typedRevocationStatusEvent]);

        expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        expect(registry.isRevoked(revocationKeyPath, {timestamp: timestamp})).resolves.toEqual(true)
      })
      it('should return a unrevoked state if the positive revocation events are in the future relative to the queried timestamp', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }

        const timestamp = GetDateForTodayPlusDays(-5);

        when(registryContractMock.filters.RevocationListStatusChanged).mockReturnValue("mockedListStatusIdentifier" as any)
        when(registryContractMock.filters.RevocationStatusChanged).mockReturnValue("mockedKeyStatusIdentifier" as any)

        const revokedTimestamp = Math.floor(GetDateForTodayPlusDays(-4).getTime()/1000);

        const typedListStatusEvent = {
          getBlock: jest.fn().mockResolvedValue({
            timestamp: revokedTimestamp
          } as Block),
          args: {
            revoked: true
          }
        } as any

        const typedRevocationStatusEvent = {
          getBlock: jest.fn().mockResolvedValue({
            timestamp: revokedTimestamp
          } as Block),
          args: {
            revoked: true
          }
        } as any

        when(registryContractMock.queryFilter).calledWith("mockedListStatusIdentifier" as any).mockResolvedValue([typedListStatusEvent]);
        when(registryContractMock.queryFilter).calledWith("mockedKeyStatusIdentifier" as any).mockResolvedValue([typedRevocationStatusEvent]);

        expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        expect(registry.isRevoked(revocationKeyPath, {timestamp: timestamp})).resolves.toEqual(false)
      })
      it('should return an unrevoked state if there are no revocation events', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }

        const timestamp = GetDateForTodayPlusDays(-5);

        when(registryContractMock.queryFilter).mockResolvedValue([]);

        expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        expect(registry.isRevoked(revocationKeyPath, {timestamp: timestamp})).resolves.toEqual(false)
      })
      // TODO: FIX ERROR HANDLING WITH NEW EVENT TYPES
      it.skip('should throw an error if the events cannot be fetched', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }

        const timestamp = GetDateForTodayPlusDays(-5);

        when(registryContractMock.filters.RevocationListStatusChanged).mockReturnValue({address: "", topics: [""]} as any)
        when(registryContractMock.filters.RevocationStatusChanged).mockReturnValue({address: "", topics: [""]} as any)
        when(registryContractMock.queryFilter).calledWith({
          address: "",
          topics: [""]
        } as any).mockResolvedValue([{} as any, {} as any]);
        when(registryContractMock.queryFilter).mockRejectedValue(new Error("mocked error"));
        expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);

        expect(registry.isRevoked(revocationKeyPath, {timestamp: timestamp})).rejects.toThrow(Error)
      })
    })

    describe('input verification', () => {
      describe('namespace in revocationKeyPath', () => {
        it('should notice emptiness', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: "",
            list: keccak256(toUtf8Bytes("listname")),
            revocationKey: keccak256(toUtf8Bytes("revocationKey"))
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
        it('should notice invalid address', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: keccak256(toUtf8Bytes("invalidaddress")),
            list: keccak256(toUtf8Bytes("listname")),
            revocationKey: keccak256(toUtf8Bytes("revocationKey"))
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
      })
      describe('for list in revocationKeyPath', () => {
        it('should notice emptiness', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: "",
            revocationKey: keccak256(toUtf8Bytes("revocationKey"))
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
        it('should notice invalid bytes32', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: validAddress,
            revocationKey: keccak256(toUtf8Bytes("revocationKey"))
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
      })
      describe('for revocationKey in revocationKeyPath', () => {
        it('should notice emptiness', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: keccak256(toUtf8Bytes("listname")),
            revocationKey: ""
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
        it('should notice invalid bytes32', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: keccak256(toUtf8Bytes("listname")),
            revocationKey: validAddress
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
      })
    })
  })

  describe('changeStatus input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationStatus: boolean = true;
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }
      expect(registry.changeStatus(revocationStatus, revocationKeyPath)).resolves;
      expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatus).toHaveBeenCalledWith(revocationStatus, revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey);
    })
    describe('namespace in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: "",
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: validAddress,
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revocationKey in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: ""
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: validAddress
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('changeStatusDelegated input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationStatus: boolean = true;
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }
      expect(registry.changeStatusDelegated(revocationStatus, revocationKeyPath)).resolves;
      expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledWith(revocationStatus, revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey);
    })
    describe('namespace in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: "",
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: validAddress,
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revocationKey in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: ""
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: validAddress
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('changeStatusSigned input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }
      const changeStatusSignedOperation = {
        revoked: true,
        revocationKeyPath: revocationKeyPath,
        signer: validAddress,
        signature: keccak256(toUtf8Bytes("mockedSignature")),
        nonce: 0
      } as ChangeStatusSignedOperation

      when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
      await registry.changeStatusSigned(changeStatusSignedOperation);
      expect(registryContractMock.changeStatusSigned).toHaveBeenCalledWith(
        changeStatusSignedOperation.revoked,
        changeStatusSignedOperation.revocationKeyPath.namespace,
        changeStatusSignedOperation.revocationKeyPath.list,
        changeStatusSignedOperation.revocationKeyPath.revocationKey,
        changeStatusSignedOperation.signer,
        changeStatusSignedOperation.signature
      );
      expect(registryContractMock.nonces).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(1);
    })

    describe('signature in signaturish in changeStatusSignedOperation', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: "",
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid hex', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: "asd",
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
    })

    describe('signer in signaturish in changeStatusSignedOperation', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: "",
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid hex', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: keccak256(toUtf8Bytes("invalidAddress")),
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
    })

    describe('nonce in signaturish in changeStatusSignedOperation', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: "",
          nonce: undefined as any
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
      it('should notice out of date nonce', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: "",
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(1n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
    })

    describe('namespace in revocationKeyPath in changeStatusSignedOperation', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
    })

    describe('list in revocationKeyPath in changeStatusSignedOperation', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: "",
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: validAddress,
          revocationKey: keccak256(toUtf8Bytes("revocationKey"))
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
    })

    describe('revocationKey in revocationKeyPath in changeStatusSignedOperation', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("revocationList")),
          revocationKey: ""
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("revocationList")),
          revocationKey: validAddress
        }
        const changeStatusSignedOperation = {
          revoked: true,
          revocationKeyPath: revocationKeyPath,
          signer: validAddress,
          signature: keccak256(toUtf8Bytes("mockedSignature")),
          nonce: 0
        } as ChangeStatusSignedOperation

        when(registryContractMock.nonces).calledWith(changeStatusSignedOperation.signer).mockResolvedValue(0n)
        expect(registry.changeStatusSigned(changeStatusSignedOperation)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusSigned).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('generateChangeStatusSignedPayload input verification', () => {
    it('should return a ChangeStatusSignedOperation', async () => {
      const revocationStatus = true
      const nonce = 0
      const signature = "mockedSignatureasd"
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("list")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }
      when(registryContractMock.getAddress).mockResolvedValue(addressMock)
      when(signerMock.getAddress).mockResolvedValue(validAddress)
      when(signerMock.signTypedData).calledWith({
        name: EIP712DomainName,
        version: contractVersion,
        chainId: networkMock.chainId,
        verifyingContract: addressMock
      }, expect.anything(), expect.anything()).mockResolvedValue(signature)
      when(registryContractMock.nonces).calledWith(validAddress).mockResolvedValue(BigInt(nonce))
      expect(registry.generateChangeStatusSignedPayload(revocationStatus, revocationKeyPath)).resolves.toEqual({
        revoked: revocationStatus,
        revocationKeyPath: revocationKeyPath,
        signer: validAddress,
        signature: signature,
        nonce: nonce
      })
    })

    it('should return an error, because no signer was given', async () => {
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("list")),
        revocationKey: keccak256(toUtf8Bytes("revocationKey"))
      }
      expect(registryWithoutSigner.generateChangeStatusSignedPayload(true, revocationKeyPath)).rejects.toThrow(Error)
    })
  })

  describe('changeStatusesInList input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationStatus: boolean = true;
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
      }
      const revocationKeyInstructions: RevocationKeyInstruction[] = [
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey")),
          revoked: true
        },
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
          revoked: true
        },
      ];
      const revokedStatuses: boolean[] = [
        revocationKeyInstructions[0].revoked,
        revocationKeyInstructions[1].revoked,
      ]
      const revokationKeys: string[] = [
        revocationKeyInstructions[0].revocationKey,
        revocationKeyInstructions[1].revocationKey,
      ]
      expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).resolves;
      expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatusesInList).toHaveBeenCalledWith(revokedStatuses, revocationListPath.namespace, revocationListPath.list, revokationKeys);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "",
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: validAddress,
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revocationKey in revocationKeyInstruction', () => {
      it('should notice emptiness', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: "",
            revoked: true
          },
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
            revoked: true
          },
        ];
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: validAddress,
            revoked: true
          } as any,
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
            revoked: true
          },
        ];
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revoked in revocationKeyInstruction', () => {
      it('should notice emptiness', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey")),
            revoked: undefined
          } as any,
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
            revoked: true
          },
        ];
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('changeStatusesInListDelegated input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
      }
      const revocationKeyInstructions: RevocationKeyInstruction[] = [
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey")),
          revoked: true
        },
        {
          revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
          revoked: true
        },
      ];
      const revokedStatuses: boolean[] = [
        revocationKeyInstructions[0].revoked,
        revocationKeyInstructions[1].revoked,
      ]
      const revokationKeys: string[] = [
        revocationKeyInstructions[0].revocationKey,
        revocationKeyInstructions[1].revocationKey,
      ]
      expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).resolves;
      expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledWith(revokedStatuses, revocationListPath.namespace, revocationListPath.list, revokationKeys);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "",
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: validAddress,
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revocationKey in revocationKeyInstruction', () => {
      it('should notice emptiness', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: "",
            revoked: true
          },
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
            revoked: true
          },
        ];
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: validAddress,
            revoked: true
          } as any,
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
            revoked: true
          },
        ];
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revoked in revocationKeyInstruction', () => {
      it('should notice emptiness', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey")),
            revoked: undefined
          } as any,
          {
            revocationKey: keccak256(toUtf8Bytes("revocationKey2")),
            revoked: true
          },
        ];
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('changeListOwner input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
      }

      expect(registry.changeListOwner(revocationListPath, validAddress)).resolves;
      expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeListOwner).toHaveBeenCalledWith(validAddress, revocationListPath.namespace, revocationListPath.list);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.changeListOwner(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.changeListOwner(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "",
        }
        expect(registry.changeListOwner(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: validAddress,
        }
        expect(registry.changeListOwner(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
    })
    describe('for newOwner', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "validAddress",
          list: keccak256(toUtf8Bytes("listname")),
        }
        expect(registry.changeListOwner(revocationListPath, "")).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        expect(registry.changeListOwner(revocationListPath, keccak256(toUtf8Bytes("invalidaddress")))).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('addListDelegate input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
      }
      const expiryDate = GetDateForTodayPlusDays(5);
      const expiryDateInSeconds = Math.floor(expiryDate.getTime()/1000);

      expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).resolves;
      expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(1);
      expect(registryContractMock.addListDelegate).toHaveBeenCalledWith(validAddress, revocationListPath.namespace, revocationListPath.list, expiryDateInSeconds);
    })
    it('should notice null revocationListPath', async () => {
      const expiryDate = GetDateForTodayPlusDays(5);

      expect(registry.addListDelegate(undefined as any, validAddress, expiryDate)).rejects.toThrow(Error);
      expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
        }

        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
        }

        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "",
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: validAddress,
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice non-hex bytes32', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cz",
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
    })
    describe('for delegate', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "validAddress",
          list: keccak256(toUtf8Bytes("listname")),
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, "", expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, keccak256(toUtf8Bytes("invalidaddress")), expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
    })
    describe('for expiryDate', () => {
      it('should notice date in the past', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }
        const expiryDate = GetDateForTodayPlusDays(-5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice null date', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.addListDelegate(revocationListPath, validAddress, undefined as any)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('removeListDelegate input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
      }

      expect(registry.removeListDelegate(revocationListPath, validAddress)).resolves;
      expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(1);
      expect(registryContractMock.removeListDelegate).toHaveBeenCalledWith(validAddress, revocationListPath.namespace, revocationListPath.list);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.removeListDelegate(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: keccak256(toUtf8Bytes("invalidaddress")),
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.removeListDelegate(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "",
        }

        expect(registry.removeListDelegate(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: validAddress,
        }

        expect(registry.removeListDelegate(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
    })
    describe('for delegate', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "validAddress",
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.removeListDelegate(revocationListPath, "")).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.removeListDelegate(revocationListPath, keccak256(toUtf8Bytes("invalidaddress")))).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('changeListStatus input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationStatus: boolean = true;
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: keccak256(toUtf8Bytes("listname")),
      }

      expect(registry.changeListStatus(revocationStatus, revocationListPath)).resolves;
      expect(registryContractMock.changeListStatus).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeListStatus).toHaveBeenCalledWith(revocationStatus, revocationListPath.namespace, revocationListPath.list);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.changeListStatus(revocationStatus, revocationListPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeListStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: keccak256(toUtf8Bytes("invalidAddress")),
          list: keccak256(toUtf8Bytes("listname")),
        }

        expect(registry.changeListStatus(revocationStatus, revocationListPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeListStatus).toHaveBeenCalledTimes(0);
      })
    })
    describe('for list in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: "",
        }

        expect(registry.changeListStatus(revocationStatus, revocationListPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeListStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationStatus: boolean = true;
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: validAddress,
        }

        expect(registry.changeListStatus(revocationStatus, revocationListPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeListStatus).toHaveBeenCalledTimes(0);
      })
    })
  })
})
