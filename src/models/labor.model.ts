import {belongsTo, Entity, model, property} from '@loopback/repository';
import { User } from './user.model';
interface Skill {
  skill: string;
  experience: number;
}
interface GeoObject {
  lat: number;
  lng: number;
}
@model()
export class Labor extends Entity {
  @property({
    type: 'number',
    id: true,
    generated: true,
  })
  id?: number;

  @property({
    type: 'array',
    itemType: 'object',
    required: true,
  })
  skills: Skill[];

  @property({
    type: 'string',
    required: true,
  })
  location: string;

  @property({
    type: 'string',
    required: true,
    validate: {
      validator: 'uniqueMobileNumber',
    },
  })
  phone: string;
  
  @property({
    type: 'number',
    required: true,
    precision: 10,
    scale: 6,
  })
  lat: number;
  
  @property({
    type: 'number',
    required: true,
    precision: 10,
    scale: 6,
  })
  lng: number;
  
  @belongsTo(() => User)
  userId: number;


  constructor(data?: Partial<Labor>) {
    super(data);
  }
}

export interface LaborRelations {
  // describe navigational properties here
}

export type LaborWithRelations = Labor & LaborRelations;
