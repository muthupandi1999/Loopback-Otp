import { authenticate, AuthenticationBindings } from '@loopback/authentication';
import { authorize } from '@loopback/authorization';
import { inject } from '@loopback/core';
import { Count, CountSchema, Filter, repository, Where } from '@loopback/repository';
import {
  del,
  get,
  getFilterSchemaFor,
  getJsonSchemaRef,
  getModelSchemaRef,
  getWhereSchemaFor,
  HttpErrors,
  param,
  post,
  put,
  requestBody,
} from '@loopback/rest';
import { securityId, UserProfile } from '@loopback/security';
import * as _ from 'lodash';

import { generateOTP, verifyOtpWithSecret } from '../helpers';
import { PasswordHasherBindings, TokenServiceBindings, UserServiceBindings } from '../keys';
import { User } from "../models";
import { Credentials, DisconnectedRepository, EmployerRepository, LaborRepository, LocationRequestRepository, OtpRepository, UserRepository, ViewerRepository } from '../repositories';
import { authorizeUser } from '../services/authorizeUser';
import { EmailService } from '../services/email.service';
import { SmsService } from '../services/phoneOtp.service';
import { BcryptHasher } from '../services/hash.password.bcrypt';
import { JWTService } from '../services/jwt-service';
import { MyUserService } from '../services/user.service';
import { validateCredentials } from '../services/validator';
import { error } from 'console';

export class UserController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
    @repository(EmployerRepository)
    public employerRepository: EmployerRepository,
    @repository(LaborRepository)
    public laborRepository: LaborRepository,
    @repository(DisconnectedRepository)
    public disconnectedRepository: DisconnectedRepository,
    @repository(LocationRequestRepository)
    public locationRepository: LocationRequestRepository,
    @repository(ViewerRepository)
    public viewerRepository: ViewerRepository,
    @repository(OtpRepository)
    public otpRepository: OtpRepository,
    // @inject(PasswordHasherBindings.PASSWORD_HASHER)
    // public hasher: BcryptHasher,
    @inject(UserServiceBindings.USER_SERVICE)
    public userService: MyUserService,
    @inject(TokenServiceBindings.TOKEN_SERVICE)
    public jwtService: JWTService,
    @inject('services.EmailService')
    private emailService: EmailService,
    @inject('services.SmsService')
    private smsService: SmsService
  ) { }

  @post('/users/signup', {
    responses: {
      '200': {
        description: 'User',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async signup(
    @requestBody({
      content: {
        'application/json': {
          schema: {
            type: 'object',
            title: 'User registeration',
            properties: {
              location: { type: 'string' },
              phone: { type: 'string' },
              skills: { type: 'array' },
              name: { type: 'string' },
              email: { type: 'string' },
              username: { type: 'string' },
              lat: { type: "number" },
              lng: { type: "number" },
              limit: { type: 'number' }
            },
            required: [
              'email',
              'location',
              'phone',
              'name',
              'username',
              "lat",
              "lng",

            ],
          },
        },
      },
    })
    userData: User & {
      location: string;
      phone: string;
      skills: Array<object>;
      lat: number;
      lng: number;
    },
  ) {

    validateCredentials(_.pick(userData, ['email']));
    userData.role = userData.skills ? ['labor'] : ['employer'];

    // userData.password = await this.hasher.hashPassword(userData.password);

    const existingUserInLabor = await this.laborRepository.findOne({
      where: { phone: userData.phone },
    });

    const existingUserInEmployer = await this.employerRepository.findOne({
      where: { phone: userData.phone }
    })


    if (existingUserInLabor || existingUserInEmployer) {
      throw new HttpErrors.NotFound(`Mobile Number Already Exists`);
    }

    const newUser = await this.userRepository.create(_.omit(userData, ["skills", "location", "phone", "lat", "lng"]));

    if (userData.skills) {

      await this.laborRepository.create({
        userId: newUser.id,
        skills: userData.skills,
        location: userData.location,
        phone: userData.phone,
        lat: userData.lat,
        lng: userData.lng,
      });

    } else {

      await this.employerRepository.create({
        userId: newUser.id,
        location: userData.location,
        phone: userData.phone,
        lat: userData.lat,
        lng: userData.lng,
      });
    }

    return newUser;

    // return _.omit(newUser, 'password');
  }

  //New one for otp varify using mobile number and otp

  @post('/users/verfiy-otp-phone', {
    responses: {
      "200": {
        description: "token",
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string'
                }
              }
            }
          }
        }
      }
    }
  })

  async verfiyOtpMobile(
    @requestBody({
      description: 'The Input otp verification',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['otp'],
            properties: {
              otp: {
                type: 'string',
                maxLength: 6,
              },
              phone: {
                type: 'string'

              },
            },
          },
        },
      },
    })
    request: {
      otp: string;
      phone: string;
    },
  ): Promise<{ token: string }> {

    let res = null;

    res = await this.employerRepository.findOne({
      where: {
        phone: request.phone
      }
    });

    if (!res)
      res = await this.laborRepository.findOne({
        where: {
          phone: request.phone
        }
      })

    var userFullDetails: any;

    if (!res) {

      throw new HttpErrors.NotFound(`User Not Found`);
    } else {

      userFullDetails = await this.userRepository.findById(res.userId);

    }

    var otpLimitForUser = await userFullDetails.limit;

    if (otpLimitForUser < 5) {

      const UserOtpDetails = await this.otpRepository.findOne({
        where: {
          userId: userFullDetails.id
        }
      });

      const secret = UserOtpDetails.otp;

      const userOtp = request.otp

      var otpValid = verifyOtpWithSecret(secret, userOtp);

      if (!otpValid) {

        if (otpLimitForUser < 5) {

          let failCount = otpLimitForUser

          await this.userRepository.updateById(userFullDetails.id, {
            limit: otpLimitForUser + 1,
          })

          throw new HttpErrors.NotFound(`you have a ${4 - failCount} remaining attempt`);

        } else {

          throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);

        }

      }

      const user = await this.userRepository.findById(userFullDetails.id);

      const userProfile = this.userService.convertToUserProfile(user);

      userProfile.role = user.role;

      userProfile.id = user.id;

      const jwt = await this.jwtService.generateToken(userProfile);

      await this.userRepository.updateById(UserOtpDetails.userId, {
        limit: 0
      })

      await this.otpRepository.deleteAll({ userId: UserOtpDetails.userId });

      return Promise.resolve({ token: jwt });

    } else {

      throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);

    }

  }

  //for email with token for find a user 

  @post('/users/verify-otp', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async verifyOTP(
    @requestBody({
      description: 'The Input otp verification',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['otp'],
            properties: {
              otp: {
                type: 'string',
                maxLength: 6,
              },
              token: {
                type: 'string'

              },
            },
          },
        },
      },
    })
    request: {
      otp: string;
      token: string;
    },
  ): Promise<{ token: string }> {

    const findUser = await this.jwtService.verifyTokenForOtp(request.token);

    const userFullDetails = await this.userRepository.findById(findUser.id);

    var otpLimitForUser = userFullDetails.limit;

    // var otpLimitForUser = await userFullDetails.limit;

    if (otpLimitForUser < 5) {

      const UserOtpDetails = await this.otpRepository.findOne({
        where: {
          userId: userFullDetails.id
        }
      });

      const secret = UserOtpDetails.otp;

      const userOtp = request.otp

      var otpValid = verifyOtpWithSecret(secret, userOtp);

      if (!otpValid) {

        if (otpLimitForUser < 5) {

          let failCount = otpLimitForUser

          await this.userRepository.updateById(userFullDetails.id, {
            limit: otpLimitForUser + 1,
          })

          throw new HttpErrors.NotFound(`you have a ${4 - failCount} remaining attempt`);

        } else {

          throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);

        }

      }

      const user = await this.userRepository.findById(userFullDetails.id);

      const userProfile = this.userService.convertToUserProfile(user);

      userProfile.role = user.role;

      userProfile.id = user.id;

      const jwt = await this.jwtService.generateToken(userProfile);


      await this.userRepository.updateById(UserOtpDetails.userId, {
        limit: 0
      })

      await this.otpRepository.deleteAll({ userId: UserOtpDetails.userId });

      return Promise.resolve({ token: jwt });

    } else {

      throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);

    }

  }

  //Login via mobile number return otp

  @post('/users/loginOtp', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                otp: {
                  type: 'number',
                },
                message: {
                  type: "string"
                }
              },
            },
          },
        },
      },
    },
  })

  async loginPhoneOtp(

    @param.query.string("phone") phone: string,

  ): Promise<{ message: string, otp: number }> {

    const labor: any = await this.laborRepository.findOne({
      where: {
        phone: phone,
      },
    });

    const employer: any = await this.employerRepository.findOne({
      where: {
        phone: phone,
      },
    });

    if (!labor && !employer) {

      throw new HttpErrors.NotFound(`user not found with this phone`);

    } else if (!employer && labor) {

      var userFullDetails = await this.userRepository.findById(labor.userId);

      const SecurityIdCon: string = userFullDetails.id.toString();

      if (!userFullDetails) {

        throw new HttpErrors.NotFound('user not found')

      } else {

        var userProfile = {
          name: userFullDetails.name,
          email: userFullDetails.email,
          [securityId]: SecurityIdCon
        }

        const { otp, secret } = await generateOTP(Number(userProfile[securityId]));

        console.log("otp", otp)

        await this.otpRepository.deleteAll({
          userId: Number(userProfile[securityId]),
          type: "LOGIN",
        });

        await this.otpRepository.create({
          userId: Number(userProfile[securityId]),
          otp: secret,
          type: "LOGIN",
          data: {},
        });

        return {
          message: 'Otp Sended Successfully',
          otp: otp
        };

      }

    } else {

      var userFullDetails = await this.userRepository.findById(employer.userId);

      const SecurityIdCon: string = userFullDetails.id.toString();

      if (!userFullDetails) {

        throw new HttpErrors.NotFound('user not found')

      } else {

        var userProfile = {
          name: userFullDetails.name,
          email: userFullDetails.email,
          [securityId]: SecurityIdCon
        }

        const { otp, secret } = await generateOTP(Number(userProfile[securityId]));

        await this.otpRepository.deleteAll({
          userId: Number(userProfile[securityId]),
          type: "LOGIN",
        });

        await this.otpRepository.create({
          userId: Number(userProfile[securityId]),
          otp: secret,
          type: "LOGIN",
          data: {},
        });

        return {
          message: 'Otp Sended Successfully',
          otp: otp
        };

      }

    }

  }

  //Login using email and return token

  @post('/users/login', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async login(
    @requestBody({
      description: 'The Input of login function',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['email'],
            properties: {
              email: {
                type: 'string',
                format: 'email',
              }

            },
          },
        },
      },
    })
    credentials: Credentials,
  ): Promise<{ message: string; token: string }> {

    const user = await this.userService.verifyCredentials(credentials);

    const userProfile = this.userService.convertToUserProfile(user);

    userProfile.id = user.id;

    const jwtOtp = await this.jwtService.generateTokenForOtp(userProfile);

    const { otp, secret } = await generateOTP(Number(userProfile[securityId]));

    await this.otpRepository.deleteAll({
      userId: Number(userProfile[securityId]),
      type: "LOGIN",
    });

    await this.otpRepository.create({
      userId: Number(userProfile[securityId]),
      otp: secret,
      type: "LOGIN",
      data: {},
    });

    await this.emailService.sendEmail(
      credentials.email,
      'Verification code for test app',
      `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
      .expiration {
        color: red;
        font-weight: bold;
      }
    </style>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Hi there,</p>
        <p>Your OTP for verifying your account on my loopback test app is:</p>
        <h3 style="font-size: 32px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p>Please enter this OTP in the verification form to complete the login process.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Thank you for using my service.</p>
      </body>
    </html>`,
    );

    return {
      message:
        'Please check your mail for verification code. (If mail not received check on the spam/junk due to this smtp is created for testing purpose)',
      token: jwtOtp
    };
    
  }

  @authenticate('jwt')
  @authorize({
    allowedRoles: ['admin'],
    voters: [authorizeUser],
  })
  @get('/users/count', {
    responses: {
      '200': {
        description: 'User model count',
        content: { 'application/json': { schema: CountSchema } },
      },
    },
  })
  async count(
    @param.query.object('where', getWhereSchemaFor(User)) where?: Where<User>,
  ): Promise<Count> {
    return this.userRepository.count(where);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @get('/users', {
    responses: {
      '200': {
        description: 'Array of User model instances',
        content: {
          'application/json': {
            schema: {
              type: 'array',
              items: getModelSchemaRef(User, { includeRelations: true }),
            },
          },
        },
      },
    },
  })
  async find(
    @param.query.object('filter', getFilterSchemaFor(User))
    filter?: Filter<User>,
  ): Promise<User[]> {
    return this.userRepository.find(filter);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @get('/users/{id}', {
    responses: {
      '200': {
        description: 'User model instance',
        content: {
          'application/json': {
            schema: getModelSchemaRef(User, { includeRelations: true }),
          },
        },
      },
    },
  })
  async findById(
    @param.path.number('id') id: number,
    @param.query.object('filter', getFilterSchemaFor(User))
    filter?: Filter<User>,
  ): Promise<User> {
    return this.userRepository.findById(id, filter);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @put('/users/{id}', {
    responses: {
      '204': {
        description: 'User PUT success',
      },
    },
  })
  async replaceById(
    @param.path.number('id') id: number,
    @requestBody() user: User,
  ): Promise<void> {
    await this.userRepository.replaceById(id, user);
  }

  @authenticate({
    strategy: 'jwt',
    options: {
      required: ['admin'],
    },
  })
  @del('/users/{id}', {
    responses: {
      '204': {
        description: 'User DELETE success',
      },
    },
  })
  async deleteById(@param.path.number('id') id: number): Promise<void> {
    await this.userRepository.deleteById(id);
  }

  @get('/users/me')
  @authenticate('jwt')
  async me(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<UserProfile> {
    // console.log(currentUser);
    currentUser.id = currentUser[securityId];
    return Promise.resolve(_.omit(currentUser, currentUser[securityId]));
  }

  @post('/users/become-a-labor')
  @authenticate('jwt')
  @authorize({
    allowedRoles: ['employer'],
    voters: [authorizeUser],
  })
  async becomeALabor(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Become a labor",
            properties: {
              skills: {
                type: 'array'
              }
            },
            required: ["skills"],
          },
        },
      },
    })
    requestData: {
      skills: Array<object>;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<User> {
    /**
     * todo add role as labor
     * add skills
     */
    const user = await this.userRepository.findById(currentUser.id)
    if (user.role.includes('labor')) {
      throw new HttpErrors.BadRequest(`You're already a labor`)
    }
    user.role.push('labor')
    await this.userRepository.updateById(currentUser.id, user);

    const employerInfo = await this.employerRepository.findOne({ where: { userId: currentUser.id } });

    await this.laborRepository.create({
      userId: currentUser.id,
      skills: requestData.skills,
      location: employerInfo.location,
      phone: employerInfo.phone
    })

    return user;
  }

  @authenticate('jwt')
  @authorize({
    allowedRoles: ['employer', 'labor'],
    voters: [authorizeUser],
  })
  @get('/get-labor/{id}', {
    responses: {
      '200': {
        description: 'Get Labors',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getLaborByID(
    @param.path.number('id') userId: number,

    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<object> {


    const user = await this.userRepository.findOne({
      where: {
        id: userId,
        isDelete: false
      }
    })


    let profile = null
    profile = await this.laborRepository.findOne({
      where: { userId: user.id }
    })


    if (!profile) {
      return {
        message: 'Labor not found'
      }
    }

    /**
     * adding profile viewed for labor
     */
    await this.viewerRepository.create({
      laborId: user.id,
      viewerId: currentUser.id
    })

    return {
      user,
      profile
    }
  }


  @get('/get-laborby-guest/{id}', {
    responses: {
      '200': {
        description: 'Get Labors',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getLaborByIDforLabor(
    @param.path.number('id') userId: number,
    @param.query.object('viewer') viewer: object
  ): Promise<object> {
    const user = await this.userRepository.findOne({
      where: {
        id: userId,
        isDelete: false
      }
    })
    if (!user) {
      return {
        message: 'Labor not found'
      }
    }
    let profile = null
    profile = await this.laborRepository.findOne({
      where: { userId: user.id }
    })
    if (!profile) {
      return {
        message: 'Labor not found'
      }
    }

    /**
     * adding profile viewed for labor
     */
    await this.viewerRepository.create({
      laborId: user.id,
      viewerId: -1,
      viewerDetail: viewer
    })

    return {
      user,
      profile
    }
  }


  /**
   * Todo:
   *  make relation between user table and viewer table
   *  pagination
   */

  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor'],
    voters: [authorizeUser],
  })
  @get('/get-profile-views', {
    responses: {
      '200': {
        description: 'Get Labors',
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getProfileViews(
    @param.query.date('startDate') startDate: Date,
    @param.query.date('endDate') endDate: Date,
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
  ): Promise<object> {
    let profile = null
    profile = await this.viewerRepository.find({
      where: {
        laborId: currentUser.id,
        createdAt: {
          between: [startDate, endDate]
        }
      }
    })
    return {
      profile
    }
  }

  @post("/users/verify-otp-number")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["employer", "labor"],
    voters: [authorizeUser],
  })
  async verifyOTPForNumber(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Verify otp for number",
            properties: {
              otp: {
                type: "string",
                maxLength: 6,
              },
            },
            required: ["otp"],
          },
        },
      },
    })
    requestData: {
      otp: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {

    const otpUser: any = await this.otpRepository.findOne({

      where: {
        // otp: request.otp,
        userId: currentUser.id,
        type: "CHANGE_NUMBER",
      },

    });

    var userFullDetails = await this.userRepository.findById(otpUser.userId);

    var otpLimitForUser = userFullDetails.limit;

    if (otpLimitForUser < 5) {

      const secret = otpUser.otp;

      const userOtp = requestData.otp;

      var otpValid = verifyOtpWithSecret(secret, userOtp);

      if (!otpValid) {

        if (otpLimitForUser < 5) {

          let failCount = otpLimitForUser

          await this.userRepository.updateById(userFullDetails.id, {
            limit: otpLimitForUser + 1,
          })

          throw new HttpErrors.NotFound(`you have a ${4 - failCount} remaining attempt`);

        } else {

          throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);

        }

      }

      const user = await this.userRepository.findById(userFullDetails.id);

      const t = await this.employerRepository.findOne({});
      console.log(t.userId);

      let employer = await this.employerRepository.findOne({
        where: { userId: user.id },
      });
      let labor = await this.laborRepository.findOne({
        where: { userId: user.id },
      });
      console.log(
        await this.laborRepository.findOne({
          where: { userId: user.id },
        })
      );
      console.log(
        await this.employerRepository.findOne({
          where: { userId: user.id },
        })
      );
      if (employer) {
        employer.phone = otpUser.data.number;
        console.log(otpUser.data.number);
        await this.employerRepository.updateById(employer.id, employer);
      }

      if (labor) {
        labor.phone = otpUser.data.number;
        console.log(otpUser.data.number);

        await this.laborRepository.updateById(labor.id, labor);
      }
      await this.otpRepository.deleteAll({
        userId: currentUser.id,
        type: "CHANGE_NUMBER",
      });
      return {
        message: "Your mobile number successfully changed!",
      };

    } else {
      throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);
    }

  }

  @post("/users/update-number")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["employer", "labor"],
    voters: [authorizeUser],
  })
  async updatePhone(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Verify otp for number",
            properties: {
              number: {
                type: "string",
              },
            },
            required: ["number"],
          },
        },
      },
    })
    requestData: {
      number: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    const user = await this.userRepository.findById(currentUser.id)


    const { otp, secret } = await generateOTP(currentUser.id);

    await this.otpRepository.deleteAll({
      userId: currentUser.id,
      type: "CHANGE_NUMBER",
    });
    await this.otpRepository.create({
      userId: currentUser.id,
      otp: secret,
      type: "CHANGE_NUMBER",
      data: requestData,
    });
    await this.emailService.sendEmail(
      user.email,
      'Verification code for test app',
      `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
      .expiration {
        color: red;
        font-weight: bold;
      }
    </style>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Hi there,</p>
        <p>Your OTP for mobile number on my loopback test app is:</p>
        <h3 style="font-size: 32px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p>Please enter this OTP in the verification form to complete the mobile number change.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Thank you for using my service.</p>
      </body>
    </html>`,
    );
    return {
      message:
        'Please check your mail for verification code. (If mail not received check on the spam/junk due to this smtp is created for testing purpose)',
    };
  }



  @post("/users/update-location")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor"],
    voters: [authorizeUser],
  })
  async updateLocation(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Verify otp for number",
            properties: {
              lat: {
                type: "number",
              },
              lng: {
                type: "number",
              },
            },
            required: ["lat", "lng"],
          },
        },
      },
    })
    requestData: {
      lat: number;
      lng: number;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    await this.locationRepository.deleteAll({
      type: "LOCATION_CHANGE",
      userId: currentUser.id,
    });
    await this.locationRepository.create({
      type: "LOCATION_CHANGE",
      userId: currentUser.id,
      data: requestData,
    });
    return {
      message:
        "Request sent, Your new location will be updated after the admin verification",
    };
  }


  @get("/users/account-status")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  async viewAccountStatus(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string, data: object }> {
    const data = await this.userRepository.findById(currentUser.id, {});
    return {
      message:
        "Account status successfully fetched!",
      data: _.pick(data, ['active'])
    }
  }

  @get("/users/delete-account")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  async deleteAccount(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {
    const data = await this.userRepository.findById(currentUser.id, {});
    const { otp, secret } = await generateOTP(currentUser.id);

    console.log(currentUser.id)
    await this.otpRepository.deleteAll({
      userId: currentUser.id,
      type: "DELETE_ACCOUNT",
    });
    await this.otpRepository.create({
      userId: currentUser.id,
      otp: secret,
      type: "DELETE_ACCOUNT",
      data: { isDelete: true },
    });
    await this.emailService.sendEmail(
      data.email,
      'Verification code for test app',
      `<!DOCTYPE html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>OTP Verification</title>
        <style>
      .expiration {
        color: red;
        font-weight: bold;
      }
    </style>
      </head>
      <body>
        <h2>OTP Verification</h2>
        <p>Hi there,</p>
        <p>Your OTP for deleting your account on my loopback test app is:</p>
        <h3 style="font-size: 32px; text-align: center; margin: 20px 0;">${otp}</h3>
        <p>Please enter this OTP in the verification form to complete the delete process.</p>
        <p>If you did not request this verification, please ignore this email.</p>
        <p>Thank you for using my service.</p>
      </body>
    </html>`,
    );
    return {
      message:
        'Please check your mail for verification code. (If mail not received check on the spam/junk due to this smtp is created for testing purpose)',
    };
  }


  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  @post('/users/verify-delete-otp', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                token: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async verifyDeleteOTP(
    @requestBody({
      description: 'The Input otp verification',
      required: true,
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['otp'],
            properties: {
              otp: {
                type: 'string',
                maxLength: 6,
              },
            },
          },
        },
      },
    })
    request: {
      otp: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {


    const otp: any = await this.otpRepository.findOne({
      where: {
        // otp: request.otp,
        userId: currentUser.id,
        type: "DELETE_ACCOUNT",
      },
    });

    // var userSecret = otp.secret;

    var userFullDetails = await this.userRepository.findById(otp.userId);



    var otpLimitForUser = userFullDetails.limit;

    // var otpLimitForUser = await userFullDetails.limit;

    if (otpLimitForUser < 5) {


      // const UserOtpDetails = await this.otpRepository.findOne({
      //   where: {
      //     userId: userFullDetails.id
      //   }
      // });

      const secret = otp.otp;
      const userOtp = request.otp

      var otpValid = verifyOtpWithSecret(secret, userOtp);


      if (!otpValid) {



        if (otpLimitForUser < 5) {


          let failCount = otpLimitForUser


          await this.userRepository.updateById(userFullDetails.id, {
            limit: otpLimitForUser + 1,
          })
          throw new HttpErrors.NotFound(`you have a ${4 - failCount} remaining attempt`);

        } else {

          throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);

        }

      }

      await this.userRepository.updateById(otp?.userId, { isDelete: true });
      await this.otpRepository.deleteAll({ userId: otp.userId, type: "DELETE_ACCOUNT" });
      await this.disconnectedRepository.create({
        userId: otp.userId,
      })
      return {
        message: 'Your account has been deleted!'
      };

    } else {
      throw new HttpErrors.NotFound(`you have reached the maximum number of attempt, Please contact the admin`);
    }

  }



  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  @get('/users/enable-disable-2fa', {
    responses: {
      '200': {
        description: 'Token',
        content: {
          'application/json': {
            schema: {
              type: 'object',
              properties: {
                message: {
                  type: 'string',
                },
              },
            },
          },
        },
      },
    },
  })
  async toggle2fa(
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string, status: boolean }> {

    const user = await this.userRepository.findById(currentUser.id)
    user.tfa = !user.tfa
    await this.userRepository.update(user)
    return {
      message: '2FA has been updated',
      status: user.tfa
    };
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["labor", "employer"],
    voters: [authorizeUser],
  })
  @post("/users/store-token", {
    responses: {
      "200": {
        description: "Token",
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
  async storeToken(
    @requestBody({
      description: "The Input store token",
      required: true,
      content: {
        "application/json": {
          schema: {
            type: "object",
            required: ["token"],
            properties: {
              token: {
                type: "string"
              },
            },
          },
        },
      },
    })
    request: {
      token: string;
    },
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ): Promise<{ message: string }> {


    await this.userRepository.updateById(currentUser.id, { messageToken: request.token });
    return {
      message: "Token has been stored!",
    };
  }

}
