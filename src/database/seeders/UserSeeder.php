<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;

class UserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
          // Create the first user
        User::factory()->create([
            'name' => 'Md. Asif Rahman',
            'email' => 'asifrahman@gmail.com',
        ]);

        // Create the second user
        User::factory()->create([
            'name' => 'Eva Akter Meri',
            'email' => 'evaaktermeri@gmail.com',
        ]);

        // Create the third user
        User::factory()->create([
            'name' => 'Alvira Akter Yasha',
            'email' => 'alviraakteryasha@gmail.com',
        ]);


        // This will create 10 additional users with random data
        User::factory(10)->create();

        $this->command->info('Users seeded successfully!');
    }
}
