import { authenticate } from "@loopback/authentication";
import { AuthenticationBindings } from "@loopback/authentication/dist/keys";
import { authorize } from "@loopback/authorization";
import { inject } from "@loopback/core";
import { repository } from "@loopback/repository";
import {
  get,
  getJsonSchemaRef,
  getModelSchemaRef,
  param,
  patch,
  post,
  requestBody,
} from "@loopback/rest";
import * as _ from "lodash";

import { mergedData } from "../helpers";
import { PasswordHasherBindings } from "../keys";
import { Employer, Labor, User } from "../models";
import {
  EmployerRepository,
  LaborRepository,
  LocationRequestRepository,
  SettingRepository,
  UserRepository,
} from "../repositories";
import { authorizeUser } from "../services/authorizeUser";
import { BcryptHasher } from "../services/hash.password.bcrypt";
import { validateCredentials } from "../services/validator";

// Uncomment these imports to begin using these cool features!

// import {inject} from '@loopback/context';

export class AdminController {
  constructor(
    // @inject(PasswordHasherBindings.PASSWORD_HASHER)
    // public hasher: BcryptHasher,
    @repository(UserRepository)
    public userRepository: UserRepository,
    @repository(LaborRepository)
    public laborRepository: LaborRepository,
    @repository(LocationRequestRepository)
    public locationRequest: LocationRequestRepository,
    @repository(SettingRepository)
    public settingRepository: SettingRepository,
    @repository(EmployerRepository)
    public employerRepository: EmployerRepository
  ) { }

  @post("/admin", {
    responses: {
      "200": {
        description: "Admin",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async create(
    @requestBody({
      content: {
        "application/json": {
          schema: getModelSchemaRef(User, {
            title: "NewUser",
            exclude: ["id", "permissions", "additionalProp1"],
          }),
        },
      },
    })
    admin: User
  ) {
    validateCredentials(_.pick(admin, ["email"]));
    admin.role = ["admin"];
    // admin.password = await this.hasher.hashPassword(admin.password);
    const newAdmin = await this.userRepository.create(admin);

    return newAdmin;

    // return _.omit(newAdmin, "password");
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  @get("/get-employers", {
    responses: {
      "200": {
        description: "Get Employers",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getEmployers() {
    /**
     * Todo list employers
     */
    const employerQuery = {
      where: {
        role: { like: "%employer%" },
        isDelete: false
      },
    };
    const employerUsers: User[] = await this.userRepository.find(employerQuery);
    const employerIds = employerUsers
      .filter((user) => user.role.length === 1)
      .map((user) => user.id);
    const employerQuery2 = { where: { userId: { inq: employerIds } } };
    const employerData: Employer[] = await this.employerRepository.find(
      employerQuery2
    );
    return mergedData(
      employerUsers.filter((user) => user.role.length === 1),
      employerData,
      "userId",
      "id",
      "employerDetails"
    );
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  @get("/get-labors", {
    responses: {
      "200": {
        description: "Get Labors",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getLabors() {
    /**
     * Todo list labors
     */
    const laborQuery = {
      where: {
        role: { like: "%labor%" },
        not: {
          role: {
            like: "%,%",
            isDelete: false
          },
        },
      },
    };
    const laborUsers: User[] = await this.userRepository.find(laborQuery);

    const laborIds = laborUsers
      .filter((user) => user.role.length === 1)
      .map((user) => user.id);
    const laborQuery2 = { where: { userId: { inq: laborIds } } };

    const laborData: Labor[] = await this.laborRepository.find(laborQuery2);
    return mergedData(
      laborUsers.filter((user) => user.role.length === 1),
      laborData,
      "userId",
      "id",
      "laborDetails"
    );
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  @get("/get-hybrid", {
    responses: {
      "200": {
        description: "Get Labors",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getHybrid() {
    /**
     * Todo get labors + employer user
     */
    const hybridQuery = {
      where: {
        role: { like: '%"employer","labor"%' },
        isDelete: false
      },
    };
    const hybridUsers: User[] = await this.userRepository.find(hybridQuery);
    console.log(hybridUsers);
    const hybridIds = hybridUsers
      .filter((user) => user.role.length > 1)
      .map((user) => user.id);
    const hybridQuery2 = { where: { userId: { inq: hybridIds } } };

    const hybridData: Labor[] = await this.laborRepository.find(hybridQuery2);
    return mergedData(
      hybridUsers.filter((user) => user.role.length > 1),
      hybridData,
      "userId",
      "id",
      "hybridDetails"
    );
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  @get("/get-user/{id}", {
    responses: {
      "200": {
        description: "Get Labors",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async getUserByID(@param.path.number("id") userId: number): Promise<object> {
    const user = await this.userRepository.findById(userId);
    let profile = null;
    profile = await this.laborRepository.findOne({
      where: { userId: user.id },
    });

    if (!profile) {
      profile = await this.employerRepository.findOne({
        where: { userId: user.id },
      });
    }

    return {
      user,
      profile,
    };
    /**
     * Todo get user by id
     */
  }

  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  @patch("/update-user/{id}", {
    responses: {
      "200": {
        description: "Get Labors",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async updateUserStatus(
    @param.path.number("id") userId: number,
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "update user status",
            properties: {
              active: { type: "boolean" },
            },
            required: ["status"],
          },
        },
      },
    })
    requestData: {
      active: boolean;
    }
  ) {
    /**
     * Todo Activate/De-activate user
     */
    await this.userRepository.updateById(userId, {
      active: requestData.active,
    });
    return {
      message: "User staus has been updated",
    };
  }
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  @patch("/admin/update-setting", {
    responses: {
      "200": {
        description: "Admin",
        content: {
          schema: getJsonSchemaRef(User),
        },
      },
    },
  })
  async updateKm(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "update km",
            properties: {
              km: {
                type: "number",
              },
            },
            required: ["radius"],
          },
        },
      },
    })
    requestData: {
      radius: number;
    }
  ) {
    let setting = await this.settingRepository.findOne();
    let updated;
    console.log(setting);
    if (setting) {
      updated = await this.settingRepository.updateById(
        setting.id,
        requestData
      );
    } else {
      setting = await this.settingRepository.create(requestData);
      updated = await this.settingRepository.updateById(
        setting.id,
        requestData
      );
    }
    return {
      msg: "Updated successfully",
      data: updated,
    };
  }


  @get("/admin/get-location-request")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  async getLocationChangeRequest(
  ): Promise<object> {
    let location = await this.locationRequest.find()
    return location;
  }


  @get('/admin/reset-otp-limit')
  @authenticate('jwt')
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })

  async resetOtpLimit(
    @param.query.number("userId") userId: number,
  ): Promise<{ message: string }> {

    let user: any = await this.userRepository.findById(userId);

    if (!user) {
      return {
        message: "User not found"
      }
    }

    await this.userRepository.updateById(user.id, {
      limit: 0
    })

    return {
      message:
        "Otp reset successfully!",
    };
  }

  @get("/admin/verify-location")
  @authenticate("jwt")
  @authorize({
    allowedRoles: ["admin"],
    voters: [authorizeUser],
  })
  async verifyLocation(
    @param.query.number("laborId") laborId: number,
    @param.query.boolean("allowed") allowed: boolean
  ): Promise<{ message: string }> {
    let location: any = await this.locationRequest.findOne({
      where: {
        type: "LOCATION_CHANGE",
        userId: laborId,
      },
    });
    await this.locationRequest.deleteAll({
      type: "LOCATION_CHANGE",
      userId: laborId,
    });
    console.log(location)
    if (allowed) {
      let labourDetail = await this.laborRepository.findOne({ where: { userId: location.userId } });
      labourDetail.lat = location.data.lat
      labourDetail.lng = location.data.lng
      await this.laborRepository.updateById(labourDetail.id, labourDetail)
      return {
        message:
          "Location is successfully verified!",
      };
    } else {
      return {
        message: "Location updation is rejected!"
      }
    }
  }
}
