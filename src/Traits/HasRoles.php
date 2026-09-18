<?php

namespace Maklad\Permission\Traits;

use Illuminate\Support\Collection;
use Illuminate\Contracts\Pagination\Paginator;
use Illuminate\Contracts\Pagination\LengthAwarePaginator;
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

    public function getRoleClass()
    {
        if ($this->roleClass === null) {
            $this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
        }
        return $this->roleClass;
    }

    /**
     * Query roles by the stored role IDs.
     *
     * We intentionally avoid defining a roles() relationship because Eloquent
     * treats roles() as a relationship method and will throw if it does not
     * return a Relation instance. The MongoDB driver will also write inverse IDs
     * (e.g. person_ids) into the roles collection.
     * Returning a relationship instance also makes Eloquent treat roles() as a
     * relationship, which isn't desired for one-sided role storage. Instead we
     * expose roles via an accessor and query helper that read role_ids directly.
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
        return $this->relationLoaded('roles') ? $this->getRelation('roles') : $this->rolesQuery()->get();
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
        $roles = $this->resolveRoleAssignments($roles);
        $roleIds = $roles->pluck('_id')->unique()->values()->all();
        $this->forgetLoadedRoles();

        if ($this->exists) {
            if ($roleIds !== []) {
                $this->push('role_ids', $roleIds, true);
            }
        } else {
            $this->role_ids = collect($this->role_ids ?? [])
                ->merge($roleIds)->unique()->values()->all();
            $this->save();
        }

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

        $roleIds = $roles->pluck('_id')->all();
        $this->forgetLoadedRoles();

        if ($this->exists) {
            if ($roleIds !== []) {
                $this->pull('role_ids', $roleIds);
            }
        } else {
            $this->role_ids = collect($this->role_ids ?? [])
                ->diff($roleIds)->values()->all();
            $this->save();
        }

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
        $roles = $this->resolveRoleAssignments($roles);
        $this->forgetLoadedRoles();
        $this->role_ids = $roles->pluck('_id')->unique()->values()->all();

        if ($this->exists) {
            $this->setKeysForSaveQuery($this->newQuery())->update(['role_ids' => $this->role_ids]);
            $this->syncOriginalAttribute('role_ids');
        } else {
            $this->save();
        }

        $this->forgetCachedPermissions();

        return $roles->all();
    }

    private function resolveRoleAssignments(array $roles): Collection
    {
        return collect($roles)->flatten()->map(function ($role) {
            $role = $this->getStoredRole($role);
            $this->ensureModelSharesGuard($role);

            return $role;
        });
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
        if ($this->relationLoaded('roles')) {
            return $this->roles->pluck('name');
        }

        return $this->rolesQuery()->pluck('name');
    }

    protected function forgetLoadedRoles(): void
    {
        $this->unsetRelation('roles');
    }

    public function refresh()
    {
        if (! $this->exists) {
            return $this;
        }

        $reloadRoles = $this->relationLoaded('roles');
        // Eloquent cannot reload this collection through a roles() relationship.
        $this->forgetLoadedRoles();
        parent::refresh();

        if ($reloadRoles) {
            static::loadRolesForModel($this);
        }

        return $this;
    }

    /**
     * Load roles for a single model.
     *
     * This is the eager-loading replacement for the omitted roles() relationship.
     * It keeps one-sided role storage (role_ids on the model) while still allowing
     * models to attach roles without triggering RelationNotFound errors.
     *
     * @param Model $model
     *
     * @return Model
     */
    public static function loadRolesForModel(Model $model): Model
    {
        $model->setRelation('roles', $model->rolesQuery()->get());

        return $model;
    }

    /**
     * Batch-load roles for a collection or paginator of models.
     *
     * This is the eager-loading replacement for the omitted roles() relationship.
     * It keeps one-sided role storage (role_ids on the model) while still allowing
     * paginated results to attach roles without triggering RelationNotFound errors.
     *
     * @param Collection|Paginator|LengthAwarePaginator $models
     *
     * @return Collection
     */
    public static function loadRolesFor($models): Collection
    {
        if ($models instanceof Paginator || $models instanceof LengthAwarePaginator) {
            $models = $models->getCollection();
        }

        if (! $models instanceof Collection) {
            $models = collect($models);
        }

        if ($models->isEmpty()) {
            return $models;
        }

        $roleClass = app(PermissionRegistrar::class)->getRoleClass();
        $roleIds = $models
            ->pluck('role_ids')
            ->flatten()
            ->filter()
            ->unique()
            ->values();

        if ($roleIds->isEmpty()) {
            $models->each(function (Model $model) {
                $model->setRelation('roles', collect());
            });

            return $models;
        }

        $roles = $roleClass->query()->whereIn('_id', $roleIds)->get()->keyBy('_id');

        $models->each(function (Model $model) use ($roles) {
            $roleIds = collect($model->role_ids ?? []);
            $modelRoles = $roleIds->map(function ($roleId) use ($roles) {
                return $roles->get($roleId);
            })->filter()->values();

            $model->setRelation('roles', $modelRoles);
        });

        return $models;
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
