import {factories, RevocationRegistry} from "@spherity/ethr-revocation-registry/types/ethers-contracts";
import {
  EthereumRevocationRegistryController,
  RevocationKeyInstruction,
  RevocationKeyPath,
  RevocationListPath
} from "../src";
import {Signer} from "@ethersproject/abstract-signer";
import web3 from "web3";
import {createProvider, GetDateForTodayPlusDays} from "./testUtils";
import {when} from 'jest-when'

jest.setTimeout(30000)

const validAddress = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
const web3Provider = createProvider();
describe('EthrRevocationRegistryController', () => {
  let registry: EthereumRevocationRegistryController;
  const registryContractMock = {
    isRevoked: jest.fn(),
    changeStatus: jest.fn(),
    changeStatusDelegated: jest.fn(),
    changeStatusesInList: jest.fn(),
    changeStatusesInListDelegated: jest.fn(),
    changeListOwner: jest.fn(),
    addListDelegate: jest.fn(),
    removeListDelegate: jest.fn(),
    queryFilter: jest.fn(),
    filters: {
      ListStatusChanged: jest.fn(),
      RevocationStatusChanged: jest.fn(),
    }
  } as unknown as RevocationRegistry;

  const signerMock = {

  } as unknown as Signer;
  const addressMock = "";

  beforeAll(async () => {
    registry = new EthereumRevocationRegistryController({contract: registryContractMock, signer: signerMock, address: addressMock});
  })

  afterEach(async () => {
    jest.resetAllMocks();
  })

  describe('isRevoked', () => {
    it('should work with default "latest" blockTag directly calling the contract', async () => {
      const revocationKeyPath: RevocationKeyPath = {
        namespace: validAddress,
        list: web3.utils.keccak256("listname"),
        revocationKey: web3.utils.keccak256("revocationKey")
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
        list: web3.utils.keccak256("listname"),
        revocationKey: web3.utils.keccak256("revocationKey")
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
      it('should throw an error if the events cannot be fetched', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
          revocationKey: web3.utils.keccak256("revocationKey")
        }

        const timestamp = GetDateForTodayPlusDays(-5);

        when(registryContractMock.filters.ListStatusChanged).mockReturnValue({address: "", topics: [""]})
        when(registryContractMock.filters.RevocationStatusChanged).mockReturnValue({address: "", topics: [""]})
        when(registryContractMock.queryFilter).calledWith({
          address: "",
          topics: [""]
        }).mockResolvedValue([{} as any, {} as any]);
        when(registryContractMock.queryFilter).calledWith({address: "", topics: [""]}).mockRejectedValue(new Error("mocked error"));
        expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);

        expect(registry.isRevoked(revocationKeyPath, {timestamp: timestamp})).rejects.toThrow(Error)
      })
    })

    describe('input verification', () => {
      describe('namespace in revocationKeyPath', () => {
        it('should notice emptiness', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: "",
            list: web3.utils.keccak256("listname"),
            revocationKey: web3.utils.keccak256("revocationKey")
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
        it('should notice invalid address', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: web3.utils.keccak256("invalidaddress"),
            list: web3.utils.keccak256("listname"),
            revocationKey: web3.utils.keccak256("revocationKey")
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
            revocationKey: web3.utils.keccak256("revocationKey")
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
        it('should notice invalid bytes32', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: validAddress,
            revocationKey: web3.utils.keccak256("revocationKey")
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
      })
      describe('for revocationKey in revocationKeyPath', () => {
        it('should notice emptiness', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: web3.utils.keccak256("listname"),
            revocationKey: ""
          }
          expect(registry.isRevoked(revocationKeyPath)).rejects.toThrow(Error);
          expect(registryContractMock.isRevoked).toHaveBeenCalledTimes(0);
        })
        it('should notice invalid bytes32', async () => {
          const revocationKeyPath: RevocationKeyPath = {
            namespace: validAddress,
            list: web3.utils.keccak256("listname"),
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
        list: web3.utils.keccak256("listname"),
        revocationKey: web3.utils.keccak256("revocationKey")
      }
      expect(registry.changeStatus(revocationStatus, revocationKeyPath)).resolves;
      expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatus).toHaveBeenCalledWith(revocationStatus, revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey);
    })
    describe('namespace in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: "",
          list: web3.utils.keccak256("listname"),
          revocationKey: web3.utils.keccak256("revocationKey")
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
          revocationKey: web3.utils.keccak256("revocationKey")
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
          revocationKey: web3.utils.keccak256("revocationKey")
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: validAddress,
          revocationKey: web3.utils.keccak256("revocationKey")
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revocationKey in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
          revocationKey: ""
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
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
        list: web3.utils.keccak256("listname"),
        revocationKey: web3.utils.keccak256("revocationKey")
      }
      expect(registry.changeStatusDelegated(revocationStatus, revocationKeyPath)).resolves;
      expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledWith(revocationStatus, revocationKeyPath.namespace, revocationKeyPath.list, revocationKeyPath.revocationKey);
    })
    describe('namespace in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: "",
          list: web3.utils.keccak256("listname"),
          revocationKey: web3.utils.keccak256("revocationKey")
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
          revocationKey: web3.utils.keccak256("revocationKey")
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
          revocationKey: web3.utils.keccak256("revocationKey")
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: validAddress,
          revocationKey: web3.utils.keccak256("revocationKey")
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
    })
    describe('for revocationKey in revocationKeyPath', () => {
      it('should notice emptiness', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
          revocationKey: ""
        }
        expect(registry.changeStatus(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatus).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid bytes32', async () => {
        const revocationKeyPath: RevocationKeyPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
          revocationKey: validAddress
        }
        expect(registry.changeStatusDelegated(true, revocationKeyPath)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusDelegated).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('changeStatusesInList input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationStatus: boolean = true;
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: web3.utils.keccak256("listname"),
      }
      const revocationKeyInstructions: RevocationKeyInstruction[] = [
        {
          revocationKey: web3.utils.keccak256("revocationKey"),
          revoked: true
        },
        {
          revocationKey: web3.utils.keccak256("revocationKey2"),
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
          list: web3.utils.keccak256("listname"),
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInList(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInList).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
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
          list: web3.utils.keccak256("listname"),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: "",
            revoked: true
          },
          {
            revocationKey: web3.utils.keccak256("revocationKey2"),
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
          list: web3.utils.keccak256("listname"),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: validAddress,
            revoked: true
          } as any,
          {
            revocationKey: web3.utils.keccak256("revocationKey2"),
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
          list: web3.utils.keccak256("listname"),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: web3.utils.keccak256("revocationKey"),
            revoked: undefined
          } as any,
          {
            revocationKey: web3.utils.keccak256("revocationKey2"),
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
      const revocationStatus: boolean = true;
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: web3.utils.keccak256("listname"),
      }
      const revocationKeyInstructions: RevocationKeyInstruction[] = [
        {
          revocationKey: web3.utils.keccak256("revocationKey"),
          revoked: true
        },
        {
          revocationKey: web3.utils.keccak256("revocationKey2"),
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
          list: web3.utils.keccak256("listname"),
        }
        // can be empty because the check happens before
        const revocationKeyInstructions: RevocationKeyInstruction[] = []
        expect(registry.changeStatusesInListDelegated(revocationListPath, revocationKeyInstructions)).rejects.toThrow(Error);
        expect(registryContractMock.changeStatusesInListDelegated).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
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
          list: web3.utils.keccak256("listname"),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: "",
            revoked: true
          },
          {
            revocationKey: web3.utils.keccak256("revocationKey2"),
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
          list: web3.utils.keccak256("listname"),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: validAddress,
            revoked: true
          } as any,
          {
            revocationKey: web3.utils.keccak256("revocationKey2"),
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
          list: web3.utils.keccak256("listname"),
        }
        const revocationKeyInstructions: RevocationKeyInstruction[] = [
          {
            revocationKey: web3.utils.keccak256("revocationKey"),
            revoked: undefined
          } as any,
          {
            revocationKey: web3.utils.keccak256("revocationKey2"),
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
        list: web3.utils.keccak256("listname"),
      }

      expect(registry.changeListOwner(revocationListPath, validAddress)).resolves;
      expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(1);
      expect(registryContractMock.changeListOwner).toHaveBeenCalledWith(validAddress, revocationListPath.namespace, revocationListPath.list);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: web3.utils.keccak256("listname"),
        }

        expect(registry.changeListOwner(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
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
          list: web3.utils.keccak256("listname"),
        }
        expect(registry.changeListOwner(revocationListPath, "")).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
        }
        expect(registry.changeListOwner(revocationListPath, web3.utils.keccak256("invalidaddress"))).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('addListDelegate input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: web3.utils.keccak256("listname"),
      }
      const expiryDate = GetDateForTodayPlusDays(5);
      const expiryDateInSeconds = expiryDate.getTime()/1000;

      expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).resolves;
      expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(1);
      expect(registryContractMock.addListDelegate).toHaveBeenCalledWith(validAddress, revocationListPath.namespace, revocationListPath.list, expiryDateInSeconds);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: web3.utils.keccak256("listname"),
        }

        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
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
    })
    describe('for delegate', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "validAddress",
          list: web3.utils.keccak256("listname"),
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, "", expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.changeListOwner).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
        }
        const expiryDate = GetDateForTodayPlusDays(5);

        expect(registry.addListDelegate(revocationListPath, web3.utils.keccak256("invalidaddress"), expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
    })
    describe('for expiryDate', () => {
      it('should notice date in the past', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
        }
        const expiryDate = GetDateForTodayPlusDays(-5);

        expect(registry.addListDelegate(revocationListPath, validAddress, expiryDate)).rejects.toThrow(Error);
        expect(registryContractMock.addListDelegate).toHaveBeenCalledTimes(0);
      })
    })
  })

  describe('removeListDelegate input verification', () => {
    it('should let valid parameters pass', async () => {
      const revocationListPath: RevocationListPath = {
        namespace: validAddress,
        list: web3.utils.keccak256("listname"),
      }

      expect(registry.removeListDelegate(revocationListPath, validAddress)).resolves;
      expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(1);
      expect(registryContractMock.removeListDelegate).toHaveBeenCalledWith(validAddress, revocationListPath.namespace, revocationListPath.list);
    })
    describe('namespace in revocationListPath', () => {
      it('should notice emptiness', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: "",
          list: web3.utils.keccak256("listname"),
        }

        expect(registry.removeListDelegate(revocationListPath, validAddress)).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: web3.utils.keccak256("invalidaddress"),
          list: web3.utils.keccak256("listname"),
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
          list: web3.utils.keccak256("listname"),
        }

        expect(registry.removeListDelegate(revocationListPath, "")).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
      it('should notice invalid address', async () => {
        const revocationListPath: RevocationListPath = {
          namespace: validAddress,
          list: web3.utils.keccak256("listname"),
        }

        expect(registry.removeListDelegate(revocationListPath, web3.utils.keccak256("invalidaddress"))).rejects.toThrow(Error);
        expect(registryContractMock.removeListDelegate).toHaveBeenCalledTimes(0);
      })
    })
  })
})
