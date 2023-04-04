import { genSalt, hash } from 'bcryptjs';

import { LoopbacktestApplication } from './application';
import { EmployerRepository, LaborRepository, UserRepository } from './repositories';

export async function seed(args: string[]) {
    const seederName = args.includes('--labor') ? 'labor' : 'employer';

  console.log(`Seeding ${seederName}`);
  const genrateRandomUsers = (count) => {
    const location =[
        'madurai',
        'chennai',
        'coimbatore',
        'trichy'
    ];
    const skills =[
        'carpentar',
        'painter',
        'doctor',
        'builder',
        'helper',
        'care taker'
    ];
    const geoPoints = [
      {
        lat: 9.881497358932847,
        lng: 78.0676017246041
      },
      {
        lat: 13.012365223506782, 
        lng: 80.23017701855017
      },
      {
        lat: 12.989665104200206, 
        lng: 80.22241124462478
      },
      {
        lat: 13.018555804600023, 
        lng: 80.22452918296807
      },
      {
        lat: 13.061541681490926,
        lng: 80.23335392606508
      },
      {
        lat: 13.124459506365433,
        lng: 80.2386487719233
      },
      {
        lat: 13.101425883581625,
        lng: 80.15993206349788
      },
      {
        lat: 13.083891382556995,
        lng: 80.23017701855017
      },
      {
        lat: 9.879310839697494,
        lng: 78.08379919794929
      },
      {
        lat: 10.055775360413863,
        lng: 78.1215829040581
      },
      {
        lat: 9.896880037246712, 
        lng: 78.12078795546483
      },
      {
        lat: 9.920756581295558,
        lng: 78.10130241743367
      }
    ]
    const users = []
    let laborData = {}
   
    for(let i=0; i<count;i++){
        if(seederName === 'labor'){
            laborData = {
                skills: [{
                    skill: skills[Math.floor(Math.random() * skills.length)],
                    experience: Math.floor((Math.random()*10) + 1)
                }]
            }
        }
        let geo = geoPoints[Math.floor(Math.random() * geoPoints.length)];
        console.log(geo.lat)
        console.log(geo.lng)
        users.push({
            users: {
            name: (Math.random() + 1).toString(36).substring(7),
            username: (Math.random() + 1).toString(36).substring(7),
            role: [seederName],
            email: `${(Math.random() + 1).toString(36).substring(7)}@mail.com`,
            // password: Math.random().toString(36).slice(2, 10)
        },
        profile: {
            location: location[Math.floor(Math.random() * location.length)],
            lat: geo.lat,
            lng: geo.lng,
            phone: Math.random().toString().slice(2,12),
            ...laborData
    }
})
    }
    return users
  }

  const app = new LoopbacktestApplication();
  await app.boot();

  const userRepository = await app.getRepository(UserRepository)
  let profileRepository;
  if(seederName === 'labor'){
    profileRepository = await app.getRepository(LaborRepository)
} else {
  profileRepository = await app.getRepository(EmployerRepository)
}
  const seedData = genrateRandomUsers(20)
  for await (const {users,profile} of seedData) {
    // const salt = await genSalt(10);
    // const password =  await hash(users.password, salt);
      const user = await userRepository.create({
        ...users,
      });
      await profileRepository.create({
        ...profile,
        userId: user.id
      })
  }
  // Connectors usually keep a pool of opened connections,
  // this keeps the process running even after all work is done.
  // We need to exit explicitly.
  process.exit(0);
}

seed(process.argv).catch(err => {
  console.error('Cannot seed data', err);
  process.exit(1);
});
