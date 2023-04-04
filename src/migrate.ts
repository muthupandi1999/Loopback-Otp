import {genSalt, hash} from 'bcryptjs';

import {LoopbacktestApplication} from './application';
import {FeedbackMasterRepository, UserRepository} from './repositories';

export async function migrate(args: string[]) {
    console.log(args)
    const existingSchema = args.includes('--rebuild') ? 'drop' : 'alter';
    console.log('Migrating schemas (%s existing schema)', existingSchema);

    const app = new LoopbacktestApplication();
    await app.boot();
    await app.migrateSchema({existingSchema});
    console.log('1');

    const userRepository = await app.getRepository(UserRepository)
    // Seed data
    await userRepository.deleteAll({
        where: {
            role: {like: '%admin%'}
        }
    })
    console.log('2');

    // const salt = await genSalt(10);
    // const password = await hash('Admin@123', salt);
    console.log('3');
    try {
        await userRepository.create({
            name: 'admin',
            username: 'admin',
            email: 'admin@mail.com',
            // password: password,
            role: ['admin'],
            active: true,
        });
        console.log('4');

    } catch (e) {
        console.log('error')
        console.log(e)
    }

    try {
        await generateFeedbackMaster(app)
    } catch (e) {
        console.error('error', e)
    }
    // Connectors usually keep a pool of opened connections,
    // this keeps the process running even after all work is done.
    // We need to exit explicitly.
    process.exit(0);
}

async function generateFeedbackMaster(app: LoopbacktestApplication) {
    console.log("Populating feedback master")
    const userRepository = await app.getRepository(FeedbackMasterRepository)
    await userRepository.create({type: "Support", description: "Please tell us how can we help you"})
    await userRepository.create({type: "Advertise", description: "Please tell us how can we help you"})
    await userRepository.create({type: "Sales", description: "Please tell us how can we help you"})
    await userRepository.create({type: "Other", description: "Please tell us how can we help you"})
    console.log("Populating feedback master complete")
}

migrate(process.argv).catch(err => {
    console.error('Cannot migrate database schema', err);
    process.exit(1);
});
