import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { CheckAccessControlDto } from './dto/check-access-control';
import { Signer, Wallet, ethers } from 'ethers';
import * as splitManager from '../abi/splitManager.json';
import { checkIsAllowedAddress } from 'src/helpers/managerContract';
import { GetAccessControlDto } from './dto/get-access-control';
import * as LitJsSdk from "@lit-protocol/lit-node-client";
import { LitNetwork } from '@lit-protocol/constants';
import { SiweMessage } from 'siwe';

@Injectable()
export class LitService {
  private provider: ethers.Provider;
  private managerContract: ethers.Contract;
  private litNodeClient: LitJsSdk.LitNodeClientNodeJs;
  private signer: Signer;
  private authSig: any;
  private sessionSigs: any;
  private readonly logger = new Logger(LitService.name);

  constructor(private readonly configService: ConfigService) {
    this.provider = new ethers.JsonRpcProvider(
      this.configService.get('providerURI') || '',
    );
    this.managerContract = new ethers.Contract(
      this.configService.get('managerContractAddress') || '',
      splitManager.abi,
      this.provider,
    );
    this.signer = new Wallet(this.configService.get("privateKey") || '');
    this.litNodeClient = new LitJsSdk.LitNodeClient({
      litNetwork: LitNetwork.Habanero,
      debug: false,
    });
  }

  async initializeLit() {
    await this.litNodeClient.connect();
  }

  async generateAuthSig() {
    try {
      const nonce = await this.litNodeClient.getLatestBlockhash();
      const address = await this.signer.getAddress();
  
      const domain = 'localhost';
      const origin = 'https://localhost/login';
      const statement = 'This is a test statement.';

      const expirationTime = new Date(
        Date.now() + 1000 * 60 * 60 * 24 * 7 * 10000
      ).toISOString();      
  
      const siweMessage = new SiweMessage({
        domain,
        address: address,
        statement,
        uri: origin,
        version: '1',
        chainId: 137,
        nonce,
        expirationTime,
      });
      const messageToSign = siweMessage.prepareMessage();
  
      const signature = await this.signer.signMessage(messageToSign);
  
      const authSig = {
        sig: signature,
        derivedVia: 'web3.eth.personal.sign',
        signedMessage: messageToSign,
        address: address,
      };

      const stringifySig = JSON.stringify(authSig);
      this.logger.log(`Lit Auth Signature successfully generated: ${stringifySig}`);

      this.authSig = authSig;
    } catch (error) {
      this.logger.error(`Error generating Lit Auth Signature: ${error.message}`);
    }
  }

  async checkAccessControl(body: CheckAccessControlDto): Promise<GetAccessControlDto | undefined> {
    try {
      this.logger.log(`Received request to check access control.`);
      const {
        address,
        subscriptionId,
        subscriptionCreator,
        accessControlConditions,
        ciphertext,
        dataToEncryptHash
      } = body;

      const stringifyACCs = JSON.stringify(accessControlConditions);

      this.logger.log(
        `Received parameters: address=${address}, subscriptionId=${subscriptionId} subscriptionCreator=${subscriptionCreator}
        ACC=${stringifyACCs} ciphertext=${ciphertext} dataToEncryptHash=${dataToEncryptHash}`,
      );

      if (
        !address ||
        !subscriptionId ||
        !subscriptionCreator ||
        !accessControlConditions ||
        !ciphertext ||
        !dataToEncryptHash
      ) {
        this.logger.log(`Missing required parameters.`);
        return {
          hasAccess: false,
          message: `Missing required parameters.`,
          data: null,
        };
      }

      this.logger.log(`Checking if address is allowed.`);

      const isAllowedAddress = await checkIsAllowedAddress(
        this.managerContract,
        {
          address,
          subscriptionId,
          subscriptionCreator,
        },
        this.logger,
      );

      if (!isAllowedAddress) {
        this.logger.error(`Address is not allowed.`);
        return {
          hasAccess: false,
          message: `Address is not allowed.`,
          data: null,
        };
      }

      const payload = {
        chain: "polygon",
        ciphertext,
        dataToEncryptHash,
        accessControlConditions,
        authSig: this.authSig,
      };

      this.logger.log(`DecryptRequest: ${JSON.stringify(payload)}`)

      const decryptedData: Uint8Array = await LitJsSdk.decryptToFile(
        payload,
        this.litNodeClient,
      );

      this.logger.log(`Access granted successfully.`);
      return {
        hasAccess: true,
        message: `Access granted successfully.`,
        data: decryptedData
      }
    } catch (error) {
      this.logger.error(`Failed to check access control: ${error.message}`);
      throw error;
    }
  }
}
