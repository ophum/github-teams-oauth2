// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"
	"time"

	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/google/uuid"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/user"
)

// AccessTokenCreate is the builder for creating a AccessToken entity.
type AccessTokenCreate struct {
	config
	mutation *AccessTokenMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetToken sets the "token" field.
func (atc *AccessTokenCreate) SetToken(s string) *AccessTokenCreate {
	atc.mutation.SetToken(s)
	return atc
}

// SetExpiresAt sets the "expires_at" field.
func (atc *AccessTokenCreate) SetExpiresAt(t time.Time) *AccessTokenCreate {
	atc.mutation.SetExpiresAt(t)
	return atc
}

// SetID sets the "id" field.
func (atc *AccessTokenCreate) SetID(u uuid.UUID) *AccessTokenCreate {
	atc.mutation.SetID(u)
	return atc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (atc *AccessTokenCreate) SetNillableID(u *uuid.UUID) *AccessTokenCreate {
	if u != nil {
		atc.SetID(*u)
	}
	return atc
}

// SetUserID sets the "user" edge to the User entity by ID.
func (atc *AccessTokenCreate) SetUserID(id uuid.UUID) *AccessTokenCreate {
	atc.mutation.SetUserID(id)
	return atc
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (atc *AccessTokenCreate) SetNillableUserID(id *uuid.UUID) *AccessTokenCreate {
	if id != nil {
		atc = atc.SetUserID(*id)
	}
	return atc
}

// SetUser sets the "user" edge to the User entity.
func (atc *AccessTokenCreate) SetUser(u *User) *AccessTokenCreate {
	return atc.SetUserID(u.ID)
}

// SetGroupID sets the "group" edge to the Group entity by ID.
func (atc *AccessTokenCreate) SetGroupID(id uuid.UUID) *AccessTokenCreate {
	atc.mutation.SetGroupID(id)
	return atc
}

// SetNillableGroupID sets the "group" edge to the Group entity by ID if the given value is not nil.
func (atc *AccessTokenCreate) SetNillableGroupID(id *uuid.UUID) *AccessTokenCreate {
	if id != nil {
		atc = atc.SetGroupID(*id)
	}
	return atc
}

// SetGroup sets the "group" edge to the Group entity.
func (atc *AccessTokenCreate) SetGroup(g *Group) *AccessTokenCreate {
	return atc.SetGroupID(g.ID)
}

// Mutation returns the AccessTokenMutation object of the builder.
func (atc *AccessTokenCreate) Mutation() *AccessTokenMutation {
	return atc.mutation
}

// Save creates the AccessToken in the database.
func (atc *AccessTokenCreate) Save(ctx context.Context) (*AccessToken, error) {
	atc.defaults()
	return withHooks(ctx, atc.sqlSave, atc.mutation, atc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (atc *AccessTokenCreate) SaveX(ctx context.Context) *AccessToken {
	v, err := atc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (atc *AccessTokenCreate) Exec(ctx context.Context) error {
	_, err := atc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atc *AccessTokenCreate) ExecX(ctx context.Context) {
	if err := atc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (atc *AccessTokenCreate) defaults() {
	if _, ok := atc.mutation.ID(); !ok {
		v := accesstoken.DefaultID()
		atc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (atc *AccessTokenCreate) check() error {
	if _, ok := atc.mutation.Token(); !ok {
		return &ValidationError{Name: "token", err: errors.New(`ent: missing required field "AccessToken.token"`)}
	}
	if _, ok := atc.mutation.ExpiresAt(); !ok {
		return &ValidationError{Name: "expires_at", err: errors.New(`ent: missing required field "AccessToken.expires_at"`)}
	}
	return nil
}

func (atc *AccessTokenCreate) sqlSave(ctx context.Context) (*AccessToken, error) {
	if err := atc.check(); err != nil {
		return nil, err
	}
	_node, _spec := atc.createSpec()
	if err := sqlgraph.CreateNode(ctx, atc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	if _spec.ID.Value != nil {
		if id, ok := _spec.ID.Value.(*uuid.UUID); ok {
			_node.ID = *id
		} else if err := _node.ID.Scan(_spec.ID.Value); err != nil {
			return nil, err
		}
	}
	atc.mutation.id = &_node.ID
	atc.mutation.done = true
	return _node, nil
}

func (atc *AccessTokenCreate) createSpec() (*AccessToken, *sqlgraph.CreateSpec) {
	var (
		_node = &AccessToken{config: atc.config}
		_spec = sqlgraph.NewCreateSpec(accesstoken.Table, sqlgraph.NewFieldSpec(accesstoken.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = atc.conflict
	if id, ok := atc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := atc.mutation.Token(); ok {
		_spec.SetField(accesstoken.FieldToken, field.TypeString, value)
		_node.Token = value
	}
	if value, ok := atc.mutation.ExpiresAt(); ok {
		_spec.SetField(accesstoken.FieldExpiresAt, field.TypeTime, value)
		_node.ExpiresAt = value
	}
	if nodes := atc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.UserTable,
			Columns: []string{accesstoken.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_access_tokens = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := atc.mutation.GroupIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   accesstoken.GroupTable,
			Columns: []string{accesstoken.GroupColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.group_access_tokens = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.AccessToken.Create().
//		SetToken(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.AccessTokenUpsert) {
//			SetToken(v+v).
//		}).
//		Exec(ctx)
func (atc *AccessTokenCreate) OnConflict(opts ...sql.ConflictOption) *AccessTokenUpsertOne {
	atc.conflict = opts
	return &AccessTokenUpsertOne{
		create: atc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (atc *AccessTokenCreate) OnConflictColumns(columns ...string) *AccessTokenUpsertOne {
	atc.conflict = append(atc.conflict, sql.ConflictColumns(columns...))
	return &AccessTokenUpsertOne{
		create: atc,
	}
}

type (
	// AccessTokenUpsertOne is the builder for "upsert"-ing
	//  one AccessToken node.
	AccessTokenUpsertOne struct {
		create *AccessTokenCreate
	}

	// AccessTokenUpsert is the "OnConflict" setter.
	AccessTokenUpsert struct {
		*sql.UpdateSet
	}
)

// SetToken sets the "token" field.
func (u *AccessTokenUpsert) SetToken(v string) *AccessTokenUpsert {
	u.Set(accesstoken.FieldToken, v)
	return u
}

// UpdateToken sets the "token" field to the value that was provided on create.
func (u *AccessTokenUpsert) UpdateToken() *AccessTokenUpsert {
	u.SetExcluded(accesstoken.FieldToken)
	return u
}

// SetExpiresAt sets the "expires_at" field.
func (u *AccessTokenUpsert) SetExpiresAt(v time.Time) *AccessTokenUpsert {
	u.Set(accesstoken.FieldExpiresAt, v)
	return u
}

// UpdateExpiresAt sets the "expires_at" field to the value that was provided on create.
func (u *AccessTokenUpsert) UpdateExpiresAt() *AccessTokenUpsert {
	u.SetExcluded(accesstoken.FieldExpiresAt)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(accesstoken.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *AccessTokenUpsertOne) UpdateNewValues() *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(accesstoken.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *AccessTokenUpsertOne) Ignore() *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *AccessTokenUpsertOne) DoNothing() *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the AccessTokenCreate.OnConflict
// documentation for more info.
func (u *AccessTokenUpsertOne) Update(set func(*AccessTokenUpsert)) *AccessTokenUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&AccessTokenUpsert{UpdateSet: update})
	}))
	return u
}

// SetToken sets the "token" field.
func (u *AccessTokenUpsertOne) SetToken(v string) *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetToken(v)
	})
}

// UpdateToken sets the "token" field to the value that was provided on create.
func (u *AccessTokenUpsertOne) UpdateToken() *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateToken()
	})
}

// SetExpiresAt sets the "expires_at" field.
func (u *AccessTokenUpsertOne) SetExpiresAt(v time.Time) *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetExpiresAt(v)
	})
}

// UpdateExpiresAt sets the "expires_at" field to the value that was provided on create.
func (u *AccessTokenUpsertOne) UpdateExpiresAt() *AccessTokenUpsertOne {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateExpiresAt()
	})
}

// Exec executes the query.
func (u *AccessTokenUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for AccessTokenCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *AccessTokenUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *AccessTokenUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: AccessTokenUpsertOne.ID is not supported by MySQL driver. Use AccessTokenUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *AccessTokenUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// AccessTokenCreateBulk is the builder for creating many AccessToken entities in bulk.
type AccessTokenCreateBulk struct {
	config
	err      error
	builders []*AccessTokenCreate
	conflict []sql.ConflictOption
}

// Save creates the AccessToken entities in the database.
func (atcb *AccessTokenCreateBulk) Save(ctx context.Context) ([]*AccessToken, error) {
	if atcb.err != nil {
		return nil, atcb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(atcb.builders))
	nodes := make([]*AccessToken, len(atcb.builders))
	mutators := make([]Mutator, len(atcb.builders))
	for i := range atcb.builders {
		func(i int, root context.Context) {
			builder := atcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*AccessTokenMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				var err error
				nodes[i], specs[i] = builder.createSpec()
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, atcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = atcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, atcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, atcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (atcb *AccessTokenCreateBulk) SaveX(ctx context.Context) []*AccessToken {
	v, err := atcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (atcb *AccessTokenCreateBulk) Exec(ctx context.Context) error {
	_, err := atcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (atcb *AccessTokenCreateBulk) ExecX(ctx context.Context) {
	if err := atcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.AccessToken.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.AccessTokenUpsert) {
//			SetToken(v+v).
//		}).
//		Exec(ctx)
func (atcb *AccessTokenCreateBulk) OnConflict(opts ...sql.ConflictOption) *AccessTokenUpsertBulk {
	atcb.conflict = opts
	return &AccessTokenUpsertBulk{
		create: atcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (atcb *AccessTokenCreateBulk) OnConflictColumns(columns ...string) *AccessTokenUpsertBulk {
	atcb.conflict = append(atcb.conflict, sql.ConflictColumns(columns...))
	return &AccessTokenUpsertBulk{
		create: atcb,
	}
}

// AccessTokenUpsertBulk is the builder for "upsert"-ing
// a bulk of AccessToken nodes.
type AccessTokenUpsertBulk struct {
	create *AccessTokenCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(accesstoken.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *AccessTokenUpsertBulk) UpdateNewValues() *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(accesstoken.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.AccessToken.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *AccessTokenUpsertBulk) Ignore() *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *AccessTokenUpsertBulk) DoNothing() *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the AccessTokenCreateBulk.OnConflict
// documentation for more info.
func (u *AccessTokenUpsertBulk) Update(set func(*AccessTokenUpsert)) *AccessTokenUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&AccessTokenUpsert{UpdateSet: update})
	}))
	return u
}

// SetToken sets the "token" field.
func (u *AccessTokenUpsertBulk) SetToken(v string) *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetToken(v)
	})
}

// UpdateToken sets the "token" field to the value that was provided on create.
func (u *AccessTokenUpsertBulk) UpdateToken() *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateToken()
	})
}

// SetExpiresAt sets the "expires_at" field.
func (u *AccessTokenUpsertBulk) SetExpiresAt(v time.Time) *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.SetExpiresAt(v)
	})
}

// UpdateExpiresAt sets the "expires_at" field to the value that was provided on create.
func (u *AccessTokenUpsertBulk) UpdateExpiresAt() *AccessTokenUpsertBulk {
	return u.Update(func(s *AccessTokenUpsert) {
		s.UpdateExpiresAt()
	})
}

// Exec executes the query.
func (u *AccessTokenUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the AccessTokenCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for AccessTokenCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *AccessTokenUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
