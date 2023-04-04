import {Entity, hasMany, model, property} from '@loopback/repository';
import { AwardsSubStatus, AwardsSubStatusWithRelations } from './awards-sub-status.model';

@model({settings: {strict: true}})
export class Awards extends Entity {
  @property({
    type: 'number',
    id: true,
    generated: true,
  })
  id?: number;

  @property({
    type: 'number',
    required: true,
  })
  laborId: number;

  @property({
    type: 'number',
    required: true,
  })
  userId: number;


  @property({
    type: 'date',
    required: true,
    default: () => new Date(),
    mysql: {
      columnName: 'created_at',
      dataType: 'timestamp',
      nullable: false,
    },
  })
  createdAt: string;

  @property({
    type: 'date',
    required: true,
    default: () => new Date(),
    mysql: {
      columnName: 'updated_at',
      dataType: 'datetime',
      nullable: false,
      updateDefault: { arg: 'NOW()', type: 'Fn' },
    },
  })
  updatedAt: string;

 @hasMany(() => AwardsSubStatus, {keyTo: 'jobId'})
  awardsSubStatus?: AwardsSubStatus[];

  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<Awards>) {
    super(data);
  }
}

export interface AwardsRelations {
  // describe navigational properties here
  awardsSubStatus?: AwardsSubStatusWithRelations[]
}

export type AwardsWithRelations = Awards & AwardsRelations;
