import {Entity, model, property} from '@loopback/repository';

@model({settings: {strict: true}})
export class Viewer extends Entity {
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
  viewerId: number;

  @property({
    type: 'object',
    required: true,
  })
  viewerDetail: object;

   
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
  createdAt: Date;

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
  updatedAt: Date;


  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<Viewer>) {
    super(data);
  }
}

export interface ViewerRelations {
  // describe navigational properties here
}

export type ViewerWithRelations = Viewer & ViewerRelations;
