import { service } from '@loopback/core';
import { inject } from '@loopback/context';
import Nexmo from 'nexmo';

export interface SmsRequest {
    to: string;
    text: string;
}

export interface SmsService {
    sendSms(request: SmsRequest): Promise<void>;
}

export class SmsService implements SmsService {
    private nexmo: Nexmo;

    constructor(
        @inject('sms.apiKey') private apiKey: string,
        @inject('sms.apiSecret') private apiSecret: string,
        @inject('sms.from') private from: string,
    ) {
        this.nexmo = new Nexmo({ apiKey, apiSecret });
    }

    async sendSms(request: SmsRequest): Promise<void> {
        const option = {
            type: 'unicode'
        }
        await this.nexmo.message.sendSms(this.from, request.to, request.text, option, (err, responseData) => {
            if (err) {
                console.log(err);
            } else {
                if (responseData.messages[0]['status'] === "0") {
                    console.log("Message sent successfully.");
                } else {
                    console.log(`Message failed with error: ${responseData.messages[0]['error-text']}`);
                }
            }
        });
    }
}
