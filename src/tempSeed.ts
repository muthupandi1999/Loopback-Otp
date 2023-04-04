import { genSalt, hash } from 'bcryptjs';

import { LoopbacktestApplication } from './application';
import {  UserRepository } from './repositories';

export async function seedm(args: string[]) {
   

  const app = new LoopbacktestApplication();
  await app.boot();

  const userRepository = await app.getRepository(UserRepository)

 const customers = await userRepository.find({})
 console.log(customers)
  for (const customer of customers) {
    customer.delete = false;
    await userRepository.update(customer);
  }

  // Connectors usually keep a pool of opened connections,
  // this keeps the process running even after all work is done.
  // We need to exit explicitly.
  process.exit(0);
}

seedm(process.argv).catch(err => {
  console.error('Cannot seed data', err);
  process.exit(1);
});
