import { authenticate, AuthenticationBindings } from '@loopback/authentication';
import { authorize } from '@loopback/authorization';
import { Filter, Options, repository } from '@loopback/repository';
import { get, getJsonSchemaRef, HttpErrors, param, post, requestBody } from '@loopback/rest';
import { inject } from '@loopback/core';
import _ from 'lodash'
import { Awards, Labor, User } from '../models';
import { AwardsRepository, AwardsSubStatusRepository, EmployerRepository, LaborRepository, SettingRepository, UserRepository } from '../repositories';
import { authorizeUser } from '../services/authorizeUser';
import { UserProfile } from '@loopback/security';
import { mergedData } from '../helpers';
interface Skill {
  skill: string;
  experience: number;
}
export class JobController {
  constructor(
    @repository(UserRepository)
    public userRepository: UserRepository,
    @repository(EmployerRepository)
    public employerRepository: EmployerRepository,
    @repository(SettingRepository)
    public settingRepository: SettingRepository,
    @repository(LaborRepository)
    public laborRepository: LaborRepository,
    @repository(AwardsRepository)
    public awardRepository: AwardsRepository,
    @repository(AwardsSubStatusRepository)
    public awardSubRepository: AwardsSubStatusRepository
  ) {}

  @post("/job/search", {
    responses: {
      "200": {
        description: "Search for labor",
        content: {
          schema: getJsonSchemaRef(Labor),
        },
      },
    },
  })
  async laborSearch(
    @param.query.number('limit') limit: number,
    @param.query.number('page') page: number,
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Search for labor",
            properties: {
              latitude: { type: "number" },
              longitude: { type: "number" },
              skill: { type: "string" },
            },
            required: ["location", "skills"],
          },
        },
      },
    })
    requestData: {
      latitude: number;
      longitude: number;
      skill: string;
    }
  ) {

    const setting = await this.settingRepository.findOne({})
    console.log(setting.radius)
    const search = await this.laborRepository.execute(`
    SELECT *, (
      6371 *
      acos(cos(radians(${requestData.latitude})) * 
      cos(radians(lat)) * 
      cos(radians(lng) - 
      radians(${requestData.longitude})) + 
      sin(radians(${requestData.latitude})) * 
      sin(radians(lat)))
   ) AS distance FROM Labor 
   WHERE skills LIKE '%\"skill\":\"${requestData.skill}\"%' 
   HAVING distance < ${setting.radius}
   ORDER BY distance 
   LIMIT 0, 20;
    `);

    console.log(search)

    const laborIds = search.map(labor => labor.userId);
    const userQuery = {where: {id: {inq: laborIds}, active: true, isDelete: false}}; 
    const filter: Filter<Awards> = {
      ...userQuery,
      limit: limit,
      offset: (page-1) * limit,
    };
    const options: Options = {
      limit: limit
    };

    const userData: any = await this.userRepository.findPaginated(filter, options);
    console.log(userData)
    console.log(laborIds)
    return {
      ...userData,
      data: mergedData(userData.data, search, 'userId', 'id', 'laborDetails')
    }

  }




  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor'],
    voters: [authorizeUser],
  })
  @post("/job/add-skill", {
    responses: {
      "200": {
        description: "add new skill for labor",
        content: {
          schema: getJsonSchemaRef(Labor),
        },
      },
    },
  })
  async addSkills(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "add skills for labor",
            properties: {
              skills: { type: "array" },
            },
            required: ["skills"],
          },
        },
      },
    })
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
    requestData: {
      skills: Array<Skill>;
    }
  ) {
    const labor = await this.laborRepository.findOne({where: {
      userId: currentUser.id
    }})

    // console.log(_.uniqBy(labor.skills, 'skill'))
    requestData.skills.forEach(d => {
      labor.skills.push(d)
    })
    // labor.skills = _.uniqBy(labor.skills, 'skill')
    labor.skills = _.uniqBy(labor.skills.reverse(), 'skill')
    await this.laborRepository.updateById(labor.id, labor);
    return labor
  }


  
  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor'],
    voters: [authorizeUser],
  })
  @post("/job/delete-skill", {
    responses: {
      "200": {
        description: "add new skill for labor",
        content: {
          schema: getJsonSchemaRef(Labor),
        },
      },
    },
  })
  async removeSkills(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "remove skills for labor",
            properties: {
              skills: { type: "array" },
            },
            required: ["skills"],
          },
        },
      },
    })
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
    requestData: {
      skills: Array<Skill>;
    }
  ) {
    const labor = await this.laborRepository.findOne({where: {
      userId: currentUser.id
    }})
    labor.skills = _.uniqBy(labor.skills.reverse(), 'skill')

    // console.log(_.uniqBy(labor.skills, 'skill'))
    requestData.skills.forEach(d => {
      labor.skills.splice(labor.skills.indexOf(d), 1)
    })
    // labor.skills = _.uniqBy(labor.skills, 'skill')
    await this.laborRepository.updateById(labor.id, labor);
    return labor
  }


  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor', 'employer'],
    voters: [authorizeUser],
  })
  @post("/job/award", {
    responses: {
      "200": {
        description: "Search for labor",
        content: {
          schema: getJsonSchemaRef(Labor),
        },
      },
    },
  })
  async awardJob(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Awarding a job",
            properties: {
              laborID: { type: "number" },
              message: { type: "string" },
            },
            required: ["laborID", "message"],
          },
        },
      },
    })
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
    requestData: {
      laborID: number;
      message: string;
    }
  ) {
    const isLabor = await this.laborRepository.findOne({where: {
      userId: requestData.laborID
    }})
    if(!isLabor)
      new HttpErrors.NotFound('Labor not found')
    const awards = await this.awardRepository.create({
      laborId: requestData.laborID,
      userId:  currentUser.id,
    })
    const awardsSub = await this.awardSubRepository.create({
      jobId: awards.id,
      updatedBy: currentUser.id,
      message: requestData.message,
      status: 'Opened'
    })
    return {
      awards,
      awardsSub
    };
  }


  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor', 'employer'],
    voters: [authorizeUser],
  })
  @post("/job/update-award", {
    responses: {
      "200": {
        description: "Search for labor",
        content: {
          schema: getJsonSchemaRef(Labor),
        },
      },
    },
  })
  async updateAward(
    @requestBody({
      content: {
        "application/json": {
          schema: {
            type: "object",
            title: "Updating a award",
            properties: {
              jobId: { type: "number" },
              message: { type: "string" },
              status: { type: "string" },
            },
            required: ["jobId", "message", "status"],
          },
        },
      },
    })
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile,
    requestData: {
      jobId: number;
      message: string;
      status: string;
    }
  ) {
    const job = await this.awardSubRepository.findOne({
      where: {jobId: requestData.jobId}
    })
    if(!job)
      throw new HttpErrors.NotFound(`No award found`)
    const award = await this.awardRepository.findById(requestData.jobId)
    if(award.userId === currentUser.id || award.laborId === currentUser.id){
      const updatedJob = await this.awardSubRepository.create({
        jobId: job.id,
        status: requestData.status,
        message: requestData.message,
        updatedBy: currentUser.id
      })
      return updatedJob;
    } else {
      throw new HttpErrors.Unauthorized(`Access Denied. You don't have the permission to change this award`)
    }
    
  }


  @authenticate('jwt')
  @authorize({
    allowedRoles: ['labor', 'employer'],
    voters: [authorizeUser],
  })
  @get("/job/list-job", {
    responses: {
      "200": {
        description: "Listing job",
        content: {
          schema: getJsonSchemaRef(Labor),
        },
      },
    },
  })
  async getJobList(
    @param.query.number('limit') limit: number,
    @param.query.number('page') page: number,
    @param.query.boolean('isOffered') isOffered: boolean,
    @inject(AuthenticationBindings.CURRENT_USER)
    currentUser: UserProfile
  ) {
    let wherQuery;
    wherQuery = {
      where: {
        laborId: currentUser.id
      }
    }
    if(isOffered){
      wherQuery = {
        where: {
          userId: currentUser.id
        }
      }
    }
    const filter: Filter<Awards> = {
      ...wherQuery,
      include: [
        {
          relation: 'awardsSubStatus',
        },
      ],
      limit: limit,
      offset: page-1 * limit,
      // order: ['property1 ASC', 'property2 DESC'],
    };


    const options: Options = {
      limit: limit
      // fields: {
      //   property1: true,
      //   property2: false,
      // },
      // include: [
      //   {
      //     relation: 'relatedModel',
      //     scope: {
      //       where: {
      //         property3: 'value3',
      //       },
      //     },
      //   },
      // ],
    };


    return await this.awardRepository.findPaginated(filter, options)
    const job = await this.awardRepository.find(wherQuery)
    if(!job)
      throw new HttpErrors.NotFound(`No award found`)


      return job
    
  }
}



