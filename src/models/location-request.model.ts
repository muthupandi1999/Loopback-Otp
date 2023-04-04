import {Entity, model, property} from '@loopback/repository';

@model({settings: {strict: true}})
export class LocationRequest extends Entity {
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
    type: 'string',
    required: true,
  })
  type: string;

  @property({
    type: 'object',
    required: true,
  })
  data: object;

  // Define well-known properties here

  // Indexer property to allow additional data
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  [prop: string]: any;

  constructor(data?: Partial<LocationRequest>) {
    super(data);
  }
}

export interface LocationRequestRelations {
  // describe navigational properties here
}

export type LocationRequestWithRelations = LocationRequest & LocationRequestRelations;
