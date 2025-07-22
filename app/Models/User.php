<?php

namespace App\Models;

use Illuminate\Support\Carbon;
use Laravel\Passport\HasApiTokens;
use Illuminate\Notifications\Notifiable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class User extends Authenticatable implements MustVerifyEmail
{
    /** @use HasFactory<\Database\Factories\UserFactory> */
    use HasApiTokens, HasFactory, Notifiable;

    /**
     * The attributes that are mass assignable.
     *
     * @var list<string>
     */
    protected $fillable = [
        'name',
        'email',
        'password',
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var list<string>
     */
    protected $hidden = [
        'password',
        'remember_token',
    ];

    /**
     * Define which attributes should be appended to the model's array/JSON form.
     *
     */
    protected $appends = ['role_names'];

    /**
     * Create a new personal access token
     *
     * @param string $name
     * @param int $expiryMinutes
     * @param array<string> $abilities
     * @return string The plain text token.
     */
    public function createPersonalToken(string $name, int $expiryMinutes = 1440, array $abilities = ['*'])
    {
        $token = $this->createToken($name, $abilities);
        return $token->accessToken;
    }

    /**
     * Get the roles that belong to the User.
     *
     * This defines a many-to-many relationship between the User and Role models.
     *
     * @return BelongsToMany
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, 'role_user', 'user_id', 'role_id');
    }

    /**
     * Get the user's role names as an array.
     * This is an accessor that creates a virtual attribute 'role_names'.
     *
     * @return Attribute
     */
    protected function roleNames(): Attribute
    {
        return Attribute::make(
            get: fn () => $this->roles->pluck('name')->toArray(),
            // No setter needed for a derived attribute
        );
    }
    /**
     * Check if the user has any of the specified roles.
     *
     * @param string|array<string> $roles
     * @return bool
     */
    public function hasRole(string|array $roles): bool
    {
        $roles = array_map('trim', is_array($roles) ? $roles : [$roles]);
        $roles = array_map('strtolower', $roles);

        return $this->roles()
            ->whereRaw('LOWER(name) IN (' . implode(',', array_fill(0, count($roles), '?')) . ')', $roles)
            ->exists();
    }

    /**
     * Check if the user is an admin or super admin.
     *
     * @return bool
     */
    public function isAdministrator(): bool
    {
        return $this->hasRole(['Admin', 'Super Admin']);
    }

    /**
     * Check if the user is an admin
     *
     * @return bool
     */
    public function isOnlyAdmin(): bool
    {
        return $this->hasRole('Admin');
    }

    /**
     * Check if the user is a super admin.
     *
     * @return bool
     */
    public function isSuperAdmin(): bool
    {
        return $this->hasRole('Super Admin');
    }

    /**
     * Check if the user is a subscriber.
     *
     * @return bool
     */
    public function isSubscriber(): bool
    {
        return $this->hasRole('Subscriber');
    }

    /**
     * Check if the user is a regular user.
     *
     * @return bool
     */
    public function isUser(): bool
    {
        return $this->hasRole('User');
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }
}
