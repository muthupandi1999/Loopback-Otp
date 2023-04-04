import {Entity, model, property} from '@loopback/repository';

@model({
  name: 'Employer',
  settings: {
    mysql: {
      table: 'Employer',
    },
  },
})
export class Employer extends Entity {
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
  location: string;

  @property({
    type: 'string',
    required: true,
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

  constructor(data?: Partial<Employer>) {
    super(data);
  }
}

export interface EmployerRelations {
  // describe navigational properties here
}

export type EmployerWithRelations = Employer & EmployerRelations;
