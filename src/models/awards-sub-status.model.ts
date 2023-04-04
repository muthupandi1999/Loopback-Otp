import { belongsTo, Entity, model, property } from '@loopback/repository';
import { Awards, AwardsWithRelations } from './awards.model';

@model({ settings: { strict: true } })
export class AwardsSubStatus extends Entity {
  @property({
    type: 'number',
    id: true,
    generated: true,
  })
  id?: number;


  @property({
    type: 'string',
    required: true,
  })
  status: string;

  @property({
    type: 'string',
    required: true,
  })
  message: string;

  @property({
    type: 'string',
    required: true,
  })
  updatedBy: number;


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
    type: 'datetime',
    required: true,
    mysql: {
      columnName: 'updated_at',
      dataType: 'datetime',
      nullable: false,
      updateDefault: { arg: 'NOW()', type: 'Fn' },
    },
  })
  updatedAt: string;

  // @property({
  //   type: 'date',
  //   required: true,
  //   default: () => new Date(),
  //   mysql: {
  //     columnName: 'updated_at',
  //     dataType: 'timestamp',
  //     nullable: false,
  //     updateDefault: () => new Date(),
  //   },
  // })
  // updatedAt: string;

  @belongsTo(() => Awards, { keyFrom: 'id', name: 'awards' })
  jobId: number;



  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<AwardsSubStatus>) {
    super(data);
  }
}

export interface AwardsSubStatusRelations {
  awards: AwardsWithRelations;
}
export type AwardsSubStatusWithRelations = AwardsSubStatus & AwardsSubStatusRelations;
