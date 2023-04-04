import speakeasy from "speakeasy";
import admin from "firebase-admin";
import { getMessaging } from "firebase-admin/messaging";
import { serviceAccount } from "../firebase_service";
import * as twilio from 'twilio';



const serviceAccountKey = {
  privateKey: serviceAccount.private_key,
  clientEmail: serviceAccount.client_email,
  type: serviceAccount.type,
  projectId: serviceAccount.project_id,
  private_key_id: serviceAccount.private_key_id,
  client_id: serviceAccount.client_id,
  auth_uri: serviceAccount.auth_uri,
  token_uri: serviceAccount.token_uri,
  auth_provider_x509_cert_url: serviceAccount.auth_provider_x509_cert_url,
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccountKey),
});

export const generateOTP = async (userId: number): Promise<{
  secret: any;
  otp: any;
}> => {


  // Generate a secret key
  const secret = speakeasy.generateSecret({
    length: 20,
    name: "Test App",
    issuer: "Marees",
    encoding: "base32",
    seed: userId.toString(),
  });

  // Generate a TOTP based on the secret key and current time
  const totp = speakeasy.time({
    secret: secret.base32,
    encoding: "base32",
    // step: 600, //10 mins
    // window: 60,
    step: 240,
    window: 100,
    counter: 123,
  });

  console.log("OTP:", totp); // 037455
  console.log("Secret:", secret); /**
  Secret: {
    ascii: '{<3btFNK:<;!BJvirG&M',
    hex: '7b3c336274464e4b3a3c3b21424a76697247264d',
    base32: 'PM6DGYTUIZHEWOR4HMQUESTWNFZEOJSN',
    otpauth_url: 'otpauth://totp/Test%20App?secret=PM6DGYTUIZHEWOR4HMQUESTWNFZEOJSN'
  } */

  return {
    secret: secret.base32,
    otp: totp
  };
};



export const verifyOtpWithSecret = (secret: string, otp: string) => {

 
  const isValid = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: otp,
    step: 240,
    window: 100,
    counter: 123,
  });

  if (isValid) {
    console.log('The OTP is valid.');
    return true
  } else {
    console.log('The OTP is invalid.');
    return false
  }

  // return speakeasy.totp.verify({
  //   secret: secret,
  //   encoding: 'base32',
  //   token: otp,
  //   window: window,
  // }, function (error, valid) {
  //   if (error) {
  //     console.error(error);
  //   } else {
  //     console.log(`The OTP is ${valid ? true : false}.`);
  //   }
  // });
}

export const mergedData = (
  primaryArray,
  secondaryArray,
  primeKey,
  secondaryKey,
  modifyKey
) => {
  return primaryArray.map((item) => {
    const mData = secondaryArray.find(
      (item2) => item2[primeKey] === item[secondaryKey]
    );
    if (mData) {
      item[modifyKey] = mData;
    }
    return item;
  });
};

export const sendPushNotification = async (
  token: string,
  data: object,
  notification: object
) => {
  // Send a message to the device corresponding to the provided
  // registration token.
  const message = {
    data: { ...data },
    token,
    notification: { ...notification },
  };
  console.log(message);
  const res = await getMessaging().send(message);
  console.log(res);
  if (res) {
    return true;
  }
  return false;
};

export const sendPushNotificationMulti = async (tokens, msg) => {
  const res = await getMessaging().sendMulticast({
    tokens,
    data: msg,
  });
  if (res) {
    return {
      successCount: res.successCount,
      failureCount: res.failureCount,
    };
  }
  return false;
};
