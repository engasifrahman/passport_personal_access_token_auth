<?php

namespace Database\Seeders;

use App\Models\RoleUser;
use Illuminate\Database\Seeder;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;

class RoleUserSeeder extends Seeder
{
    /**
     * Run the database seeds.
     */
    public function run(): void
    {
        RoleUser::insert([
            // Super Admin for the first user
            [
                'role_id' => 1,
                'user_id' => 1,
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Admin for the second user
            [
                'role_id' => 2,
                'user_id' => 2,
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // Subscriber for the third user
            [
                'role_id' => 3,
                'user_id' => 3,
                'created_at' => now(),
                'updated_at' => now(),
            ],

            // User for the rest of the users
            [
                'role_id' => 4,
                'user_id' => 4,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'role_id' => 4,
                'user_id' => 5,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [
                'role_id' => 4,
                'user_id' => 6,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 7,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 8,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 9,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 10,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 11,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 12,
                'created_at' => now(),
                'updated_at' => now(),
            ],
            [   'role_id' => 4,
                'user_id' => 13,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        ]);
    }
}
