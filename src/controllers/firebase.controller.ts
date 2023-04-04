import { authenticate } from '@loopback/authentication';
import { post } from '@loopback/openapi-v3';
import { repository } from '@loopback/repository';
import { requestBody } from '@loopback/rest';

import { sendPushNotification } from '../helpers';
import { UserRepository } from '../repositories';

export class FirebaseController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository
  ) {}
  @authenticate("jwt")
  @post("/firebase/send-notification", {
    responses: {
      "200": {
        description: "message",
        content: {
          "application/json": {
            schema: {
              type: "object",
              properties: {
                message: {
                  type: "string",
                },
              },
            },
          },
        },
      },
    },
  })
  async sendNotification(
    @requestBody({
      description: "The Input send message",
      required: true,
      content: {
        "application/json": {
          schema: {
            type: "object",
            required: ["notification", "data", "token"],
            properties: {
              notification: {
                type: "object"
              },
              data: {
                type: "object"
              },
              token: {
                type: "string"
              },
            },
          },
        },
      },
    })
    request: {
      data: object;
      notification: object;
      token: string;
    }
  ): Promise<{ message: string }> {
    await sendPushNotification(request.token, request.data, request.notification);
    return {
      message: "Push notification sent!",
    };
  }
}
