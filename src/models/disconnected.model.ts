import {Entity, model, property} from '@loopback/repository';

@model()
export class Disconnected extends Entity {
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
  userId: number;
  
  @property({
    type: 'date',
    required: true,
    default: () => new Date(),
    mysql: {
      columnName: 'deleted_at',
      dataType: 'timestamp',
      nullable: false,
    },
  })
  deletedAt: string;



  constructor(data?: Partial<Disconnected>) {
    super(data);
  }
}

export interface DisconnectedRelations {
  // describe navigational properties here
}

export type DisconnectedWithRelations = Disconnected & DisconnectedRelations;
