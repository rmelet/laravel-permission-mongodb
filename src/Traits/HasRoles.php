<?php

namespace Maklad\Permission\Traits;

use Illuminate\Support\Collection;
use Maklad\Permission\Contracts\RoleInterface as Role;
use Maklad\Permission\Helpers;
use Maklad\Permission\PermissionRegistrar;
use MongoDB\Laravel\Eloquent\Model;
use MongoDB\Laravel\Eloquent\Builder;
use ReflectionException;
use function collect;

/**
 * Trait HasRoles
 * @package Maklad\Permission\Traits
 */
trait HasRoles
{
    use HasPermissions;

    private $roleClass;

    public static function bootHasRoles(): void
    {
        static::deleting(function (Model $model) {
            if (isset($model->forceDeleting) && !$model->forceDeleting) {
                return;
            }

            $model->role_ids = [];
            $model->save();
        });
    }

    public function getRoleClass()
    {
        if ($this->roleClass === null) {
            $this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
        }
        return $this->roleClass;
    }

    /**
     * A model may have multiple roles.
     */
    public function roles(): Builder
    {
        return $this->rolesQuery();
    }

    /**
     * Query roles by the stored role IDs.
     *
     * We intentionally avoid a belongsToMany relationship here because the
     * MongoDB driver will write inverse IDs (e.g. person_ids) into the roles
     * collection, which can become a hotspot with large user bases. Storing the
     * role_ids on the model keeps writes one-sided while still allowing role
     * lookups via queries.
     */
    public function rolesQuery(): Builder
    {
        $roleClass = $this->getRoleClass();
        return $roleClass->query()->whereIn('_id', $this->role_ids ?? []);
    }

    /**
     * Gets the roles attribute.
     */
    public function getRolesAttribute(): Collection
    {
        return $this->rolesQuery()->get();
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param Builder $query
     * @param string|array|Role|Collection $roles
     *
     * @return Builder
     */
    public function scopeRole(Builder $query, $roles): Builder
    {
        $roles = $this->convertToRoleModels($roles);

        return $query->whereIn('role_ids', $roles->pluck('_id'));
    }

    /**
     * Assign the given role to the model.
     *
     * @param array|string|Role ...$roles
     *
     * @return array|Role|string
     * @throws ReflectionException
     */
    public function assignRole(...$roles)
    {
        $roles = collect($roles)
            ->flatten()
            ->map(function ($role) {
                return $this->getStoredRole($role);
            })
            ->each(function ($role) {
                $this->ensureModelSharesGuard($role);
            });

        $this->role_ids = collect($this->role_ids ?? [])
            ->merge($roles->pluck('_id'))
            ->unique()
            ->values()
            ->all();

        $this->save();

        $this->forgetCachedPermissions();

        return $roles->all();
    }

    /**
     * Revoke the given role from the model.
     *
     * @param array|string|Role ...$roles
     *
     * @return array|Role|string
     */
    public function removeRole(...$roles)
    {
        $roles = collect($roles)
            ->flatten()
            ->map(function ($role) {
                return $this->getStoredRole($role);
            });

        $this->role_ids = collect($this->role_ids ?? [])
            ->reject(function ($roleId) use ($roles) {
                return $roles->pluck('_id')->contains($roleId);
            })
            ->values()
            ->all();

        $this->save();

        $this->forgetCachedPermissions();

        return $roles->all();
    }

    /**
     * Remove all current roles and set the given ones.
     *
     * @param array ...$roles
     *
     * @return array|Role|string
     * @throws ReflectionException
     */
    public function syncRoles(...$roles): Role|array|string
    {
        $this->role_ids = [];
        $this->save();

        return $this->assignRole($roles);
    }

    /**
     * Determine if the model has (one of) the given role(s).
     *
     * @param string|array|Role|Collection $roles
     *
     * @return bool
     */
    public function hasRole($roles): bool
    {
        if (\is_string($roles) && str_contains($roles, '|')) {
            $roles = \explode('|', $roles);
        }

        if (\is_string($roles) || $roles instanceof Role) {
            return $this->roles->contains('name', $roles->name ?? $roles);
        }

        $roles = collect()->make($roles)->map(function ($role) {
            return $role instanceof Role ? $role->name : $role;
        });

        return !$roles->intersect($this->roles->pluck('name'))->isEmpty();
    }

    /**
     * Determine if the model has any of the given role(s).
     *
     * @param string|array|Role|Collection $roles
     *
     * @return bool
     */
    public function hasAnyRole($roles): bool
    {
        return $this->hasRole($roles);
    }

    /**
     * Determine if the model has all the given role(s).
     *
     * @param $roles
     *
     * @return bool
     */
    public function hasAllRoles(...$roles): bool
    {
        $helpers = new Helpers();
        $roles = $helpers->flattenArray($roles);

        foreach ($roles as $role) {
            if (!$this->hasRole($role)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Return Role object
     *
     * @param String|Role $role role name
     *
     * @return Role
     * @throws ReflectionException
     */
    protected function getStoredRole($role): Role
    {
        if (\is_string($role)) {
            return $this->getRoleClass()->findByName($role, $this->getDefaultGuardName());
        }

        return $role;
    }

    /**
     * Return a collection of role names associated with this user.
     *
     * @return Collection
     */
    public function getRoleNames(): Collection
    {
        return $this->rolesQuery()->pluck('name');
    }

    /**
     * Convert to Role Models
     *
     * @param $roles
     *
     * @return Collection
     */
    private function convertToRoleModels($roles): Collection
    {
        if (is_array($roles)) {
            $roles = collect($roles);
        }

        if (!$roles instanceof Collection) {
            $roles = collect([$roles]);
        }

        return $roles->map(function ($role) {
            return $this->getStoredRole($role);
        });
    }
}
