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
	"github.com/ophum/github-teams-oauth2/ent/code"
	"github.com/ophum/github-teams-oauth2/ent/group"
	"github.com/ophum/github-teams-oauth2/ent/user"
)

// CodeCreate is the builder for creating a Code entity.
type CodeCreate struct {
	config
	mutation *CodeMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetCode sets the "code" field.
func (cc *CodeCreate) SetCode(s string) *CodeCreate {
	cc.mutation.SetCode(s)
	return cc
}

// SetClientID sets the "client_id" field.
func (cc *CodeCreate) SetClientID(s string) *CodeCreate {
	cc.mutation.SetClientID(s)
	return cc
}

// SetNillableClientID sets the "client_id" field if the given value is not nil.
func (cc *CodeCreate) SetNillableClientID(s *string) *CodeCreate {
	if s != nil {
		cc.SetClientID(*s)
	}
	return cc
}

// SetScope sets the "scope" field.
func (cc *CodeCreate) SetScope(s string) *CodeCreate {
	cc.mutation.SetScope(s)
	return cc
}

// SetNillableScope sets the "scope" field if the given value is not nil.
func (cc *CodeCreate) SetNillableScope(s *string) *CodeCreate {
	if s != nil {
		cc.SetScope(*s)
	}
	return cc
}

// SetRedirectURI sets the "redirect_uri" field.
func (cc *CodeCreate) SetRedirectURI(s string) *CodeCreate {
	cc.mutation.SetRedirectURI(s)
	return cc
}

// SetNillableRedirectURI sets the "redirect_uri" field if the given value is not nil.
func (cc *CodeCreate) SetNillableRedirectURI(s *string) *CodeCreate {
	if s != nil {
		cc.SetRedirectURI(*s)
	}
	return cc
}

// SetExpiresAt sets the "expires_at" field.
func (cc *CodeCreate) SetExpiresAt(t time.Time) *CodeCreate {
	cc.mutation.SetExpiresAt(t)
	return cc
}

// SetID sets the "id" field.
func (cc *CodeCreate) SetID(u uuid.UUID) *CodeCreate {
	cc.mutation.SetID(u)
	return cc
}

// SetNillableID sets the "id" field if the given value is not nil.
func (cc *CodeCreate) SetNillableID(u *uuid.UUID) *CodeCreate {
	if u != nil {
		cc.SetID(*u)
	}
	return cc
}

// SetUserID sets the "user" edge to the User entity by ID.
func (cc *CodeCreate) SetUserID(id uuid.UUID) *CodeCreate {
	cc.mutation.SetUserID(id)
	return cc
}

// SetNillableUserID sets the "user" edge to the User entity by ID if the given value is not nil.
func (cc *CodeCreate) SetNillableUserID(id *uuid.UUID) *CodeCreate {
	if id != nil {
		cc = cc.SetUserID(*id)
	}
	return cc
}

// SetUser sets the "user" edge to the User entity.
func (cc *CodeCreate) SetUser(u *User) *CodeCreate {
	return cc.SetUserID(u.ID)
}

// AddGroupIDs adds the "groups" edge to the Group entity by IDs.
func (cc *CodeCreate) AddGroupIDs(ids ...uuid.UUID) *CodeCreate {
	cc.mutation.AddGroupIDs(ids...)
	return cc
}

// AddGroups adds the "groups" edges to the Group entity.
func (cc *CodeCreate) AddGroups(g ...*Group) *CodeCreate {
	ids := make([]uuid.UUID, len(g))
	for i := range g {
		ids[i] = g[i].ID
	}
	return cc.AddGroupIDs(ids...)
}

// Mutation returns the CodeMutation object of the builder.
func (cc *CodeCreate) Mutation() *CodeMutation {
	return cc.mutation
}

// Save creates the Code in the database.
func (cc *CodeCreate) Save(ctx context.Context) (*Code, error) {
	cc.defaults()
	return withHooks(ctx, cc.sqlSave, cc.mutation, cc.hooks)
}

// SaveX calls Save and panics if Save returns an error.
func (cc *CodeCreate) SaveX(ctx context.Context) *Code {
	v, err := cc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (cc *CodeCreate) Exec(ctx context.Context) error {
	_, err := cc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (cc *CodeCreate) ExecX(ctx context.Context) {
	if err := cc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (cc *CodeCreate) defaults() {
	if _, ok := cc.mutation.ClientID(); !ok {
		v := code.DefaultClientID
		cc.mutation.SetClientID(v)
	}
	if _, ok := cc.mutation.Scope(); !ok {
		v := code.DefaultScope
		cc.mutation.SetScope(v)
	}
	if _, ok := cc.mutation.RedirectURI(); !ok {
		v := code.DefaultRedirectURI
		cc.mutation.SetRedirectURI(v)
	}
	if _, ok := cc.mutation.ID(); !ok {
		v := code.DefaultID()
		cc.mutation.SetID(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (cc *CodeCreate) check() error {
	if _, ok := cc.mutation.Code(); !ok {
		return &ValidationError{Name: "code", err: errors.New(`ent: missing required field "Code.code"`)}
	}
	if _, ok := cc.mutation.ClientID(); !ok {
		return &ValidationError{Name: "client_id", err: errors.New(`ent: missing required field "Code.client_id"`)}
	}
	if _, ok := cc.mutation.Scope(); !ok {
		return &ValidationError{Name: "scope", err: errors.New(`ent: missing required field "Code.scope"`)}
	}
	if _, ok := cc.mutation.RedirectURI(); !ok {
		return &ValidationError{Name: "redirect_uri", err: errors.New(`ent: missing required field "Code.redirect_uri"`)}
	}
	if _, ok := cc.mutation.ExpiresAt(); !ok {
		return &ValidationError{Name: "expires_at", err: errors.New(`ent: missing required field "Code.expires_at"`)}
	}
	return nil
}

func (cc *CodeCreate) sqlSave(ctx context.Context) (*Code, error) {
	if err := cc.check(); err != nil {
		return nil, err
	}
	_node, _spec := cc.createSpec()
	if err := sqlgraph.CreateNode(ctx, cc.driver, _spec); err != nil {
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
	cc.mutation.id = &_node.ID
	cc.mutation.done = true
	return _node, nil
}

func (cc *CodeCreate) createSpec() (*Code, *sqlgraph.CreateSpec) {
	var (
		_node = &Code{config: cc.config}
		_spec = sqlgraph.NewCreateSpec(code.Table, sqlgraph.NewFieldSpec(code.FieldID, field.TypeUUID))
	)
	_spec.OnConflict = cc.conflict
	if id, ok := cc.mutation.ID(); ok {
		_node.ID = id
		_spec.ID.Value = &id
	}
	if value, ok := cc.mutation.Code(); ok {
		_spec.SetField(code.FieldCode, field.TypeString, value)
		_node.Code = value
	}
	if value, ok := cc.mutation.ClientID(); ok {
		_spec.SetField(code.FieldClientID, field.TypeString, value)
		_node.ClientID = value
	}
	if value, ok := cc.mutation.Scope(); ok {
		_spec.SetField(code.FieldScope, field.TypeString, value)
		_node.Scope = value
	}
	if value, ok := cc.mutation.RedirectURI(); ok {
		_spec.SetField(code.FieldRedirectURI, field.TypeString, value)
		_node.RedirectURI = value
	}
	if value, ok := cc.mutation.ExpiresAt(); ok {
		_spec.SetField(code.FieldExpiresAt, field.TypeTime, value)
		_node.ExpiresAt = value
	}
	if nodes := cc.mutation.UserIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2O,
			Inverse: true,
			Table:   code.UserTable,
			Columns: []string{code.UserColumn},
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(user.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_node.user_codes = &nodes[0]
		_spec.Edges = append(_spec.Edges, edge)
	}
	if nodes := cc.mutation.GroupsIDs(); len(nodes) > 0 {
		edge := &sqlgraph.EdgeSpec{
			Rel:     sqlgraph.M2M,
			Inverse: true,
			Table:   code.GroupsTable,
			Columns: code.GroupsPrimaryKey,
			Bidi:    false,
			Target: &sqlgraph.EdgeTarget{
				IDSpec: sqlgraph.NewFieldSpec(group.FieldID, field.TypeUUID),
			},
		}
		for _, k := range nodes {
			edge.Target.Nodes = append(edge.Target.Nodes, k)
		}
		_spec.Edges = append(_spec.Edges, edge)
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Code.Create().
//		SetCode(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.CodeUpsert) {
//			SetCode(v+v).
//		}).
//		Exec(ctx)
func (cc *CodeCreate) OnConflict(opts ...sql.ConflictOption) *CodeUpsertOne {
	cc.conflict = opts
	return &CodeUpsertOne{
		create: cc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Code.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (cc *CodeCreate) OnConflictColumns(columns ...string) *CodeUpsertOne {
	cc.conflict = append(cc.conflict, sql.ConflictColumns(columns...))
	return &CodeUpsertOne{
		create: cc,
	}
}

type (
	// CodeUpsertOne is the builder for "upsert"-ing
	//  one Code node.
	CodeUpsertOne struct {
		create *CodeCreate
	}

	// CodeUpsert is the "OnConflict" setter.
	CodeUpsert struct {
		*sql.UpdateSet
	}
)

// SetCode sets the "code" field.
func (u *CodeUpsert) SetCode(v string) *CodeUpsert {
	u.Set(code.FieldCode, v)
	return u
}

// UpdateCode sets the "code" field to the value that was provided on create.
func (u *CodeUpsert) UpdateCode() *CodeUpsert {
	u.SetExcluded(code.FieldCode)
	return u
}

// SetClientID sets the "client_id" field.
func (u *CodeUpsert) SetClientID(v string) *CodeUpsert {
	u.Set(code.FieldClientID, v)
	return u
}

// UpdateClientID sets the "client_id" field to the value that was provided on create.
func (u *CodeUpsert) UpdateClientID() *CodeUpsert {
	u.SetExcluded(code.FieldClientID)
	return u
}

// SetScope sets the "scope" field.
func (u *CodeUpsert) SetScope(v string) *CodeUpsert {
	u.Set(code.FieldScope, v)
	return u
}

// UpdateScope sets the "scope" field to the value that was provided on create.
func (u *CodeUpsert) UpdateScope() *CodeUpsert {
	u.SetExcluded(code.FieldScope)
	return u
}

// SetRedirectURI sets the "redirect_uri" field.
func (u *CodeUpsert) SetRedirectURI(v string) *CodeUpsert {
	u.Set(code.FieldRedirectURI, v)
	return u
}

// UpdateRedirectURI sets the "redirect_uri" field to the value that was provided on create.
func (u *CodeUpsert) UpdateRedirectURI() *CodeUpsert {
	u.SetExcluded(code.FieldRedirectURI)
	return u
}

// SetExpiresAt sets the "expires_at" field.
func (u *CodeUpsert) SetExpiresAt(v time.Time) *CodeUpsert {
	u.Set(code.FieldExpiresAt, v)
	return u
}

// UpdateExpiresAt sets the "expires_at" field to the value that was provided on create.
func (u *CodeUpsert) UpdateExpiresAt() *CodeUpsert {
	u.SetExcluded(code.FieldExpiresAt)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create except the ID field.
// Using this option is equivalent to using:
//
//	client.Code.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(code.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *CodeUpsertOne) UpdateNewValues() *CodeUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		if _, exists := u.create.mutation.ID(); exists {
			s.SetIgnore(code.FieldID)
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Code.Create().
//	    OnConflict(sql.ResolveWithIgnore()).
//	    Exec(ctx)
func (u *CodeUpsertOne) Ignore() *CodeUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *CodeUpsertOne) DoNothing() *CodeUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the CodeCreate.OnConflict
// documentation for more info.
func (u *CodeUpsertOne) Update(set func(*CodeUpsert)) *CodeUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&CodeUpsert{UpdateSet: update})
	}))
	return u
}

// SetCode sets the "code" field.
func (u *CodeUpsertOne) SetCode(v string) *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.SetCode(v)
	})
}

// UpdateCode sets the "code" field to the value that was provided on create.
func (u *CodeUpsertOne) UpdateCode() *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateCode()
	})
}

// SetClientID sets the "client_id" field.
func (u *CodeUpsertOne) SetClientID(v string) *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.SetClientID(v)
	})
}

// UpdateClientID sets the "client_id" field to the value that was provided on create.
func (u *CodeUpsertOne) UpdateClientID() *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateClientID()
	})
}

// SetScope sets the "scope" field.
func (u *CodeUpsertOne) SetScope(v string) *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.SetScope(v)
	})
}

// UpdateScope sets the "scope" field to the value that was provided on create.
func (u *CodeUpsertOne) UpdateScope() *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateScope()
	})
}

// SetRedirectURI sets the "redirect_uri" field.
func (u *CodeUpsertOne) SetRedirectURI(v string) *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.SetRedirectURI(v)
	})
}

// UpdateRedirectURI sets the "redirect_uri" field to the value that was provided on create.
func (u *CodeUpsertOne) UpdateRedirectURI() *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateRedirectURI()
	})
}

// SetExpiresAt sets the "expires_at" field.
func (u *CodeUpsertOne) SetExpiresAt(v time.Time) *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.SetExpiresAt(v)
	})
}

// UpdateExpiresAt sets the "expires_at" field to the value that was provided on create.
func (u *CodeUpsertOne) UpdateExpiresAt() *CodeUpsertOne {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateExpiresAt()
	})
}

// Exec executes the query.
func (u *CodeUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for CodeCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *CodeUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *CodeUpsertOne) ID(ctx context.Context) (id uuid.UUID, err error) {
	if u.create.driver.Dialect() == dialect.MySQL {
		// In case of "ON CONFLICT", there is no way to get back non-numeric ID
		// fields from the database since MySQL does not support the RETURNING clause.
		return id, errors.New("ent: CodeUpsertOne.ID is not supported by MySQL driver. Use CodeUpsertOne.Exec instead")
	}
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *CodeUpsertOne) IDX(ctx context.Context) uuid.UUID {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// CodeCreateBulk is the builder for creating many Code entities in bulk.
type CodeCreateBulk struct {
	config
	err      error
	builders []*CodeCreate
	conflict []sql.ConflictOption
}

// Save creates the Code entities in the database.
func (ccb *CodeCreateBulk) Save(ctx context.Context) ([]*Code, error) {
	if ccb.err != nil {
		return nil, ccb.err
	}
	specs := make([]*sqlgraph.CreateSpec, len(ccb.builders))
	nodes := make([]*Code, len(ccb.builders))
	mutators := make([]Mutator, len(ccb.builders))
	for i := range ccb.builders {
		func(i int, root context.Context) {
			builder := ccb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*CodeMutation)
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
					_, err = mutators[i+1].Mutate(root, ccb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = ccb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, ccb.driver, spec); err != nil {
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
		if _, err := mutators[0].Mutate(ctx, ccb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (ccb *CodeCreateBulk) SaveX(ctx context.Context) []*Code {
	v, err := ccb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (ccb *CodeCreateBulk) Exec(ctx context.Context) error {
	_, err := ccb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (ccb *CodeCreateBulk) ExecX(ctx context.Context) {
	if err := ccb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.Code.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.CodeUpsert) {
//			SetCode(v+v).
//		}).
//		Exec(ctx)
func (ccb *CodeCreateBulk) OnConflict(opts ...sql.ConflictOption) *CodeUpsertBulk {
	ccb.conflict = opts
	return &CodeUpsertBulk{
		create: ccb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.Code.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
func (ccb *CodeCreateBulk) OnConflictColumns(columns ...string) *CodeUpsertBulk {
	ccb.conflict = append(ccb.conflict, sql.ConflictColumns(columns...))
	return &CodeUpsertBulk{
		create: ccb,
	}
}

// CodeUpsertBulk is the builder for "upsert"-ing
// a bulk of Code nodes.
type CodeUpsertBulk struct {
	create *CodeCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.Code.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//			sql.ResolveWith(func(u *sql.UpdateSet) {
//				u.SetIgnore(code.FieldID)
//			}),
//		).
//		Exec(ctx)
func (u *CodeUpsertBulk) UpdateNewValues() *CodeUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(s *sql.UpdateSet) {
		for _, b := range u.create.builders {
			if _, exists := b.mutation.ID(); exists {
				s.SetIgnore(code.FieldID)
			}
		}
	}))
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.Code.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
func (u *CodeUpsertBulk) Ignore() *CodeUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *CodeUpsertBulk) DoNothing() *CodeUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the CodeCreateBulk.OnConflict
// documentation for more info.
func (u *CodeUpsertBulk) Update(set func(*CodeUpsert)) *CodeUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&CodeUpsert{UpdateSet: update})
	}))
	return u
}

// SetCode sets the "code" field.
func (u *CodeUpsertBulk) SetCode(v string) *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.SetCode(v)
	})
}

// UpdateCode sets the "code" field to the value that was provided on create.
func (u *CodeUpsertBulk) UpdateCode() *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateCode()
	})
}

// SetClientID sets the "client_id" field.
func (u *CodeUpsertBulk) SetClientID(v string) *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.SetClientID(v)
	})
}

// UpdateClientID sets the "client_id" field to the value that was provided on create.
func (u *CodeUpsertBulk) UpdateClientID() *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateClientID()
	})
}

// SetScope sets the "scope" field.
func (u *CodeUpsertBulk) SetScope(v string) *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.SetScope(v)
	})
}

// UpdateScope sets the "scope" field to the value that was provided on create.
func (u *CodeUpsertBulk) UpdateScope() *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateScope()
	})
}

// SetRedirectURI sets the "redirect_uri" field.
func (u *CodeUpsertBulk) SetRedirectURI(v string) *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.SetRedirectURI(v)
	})
}

// UpdateRedirectURI sets the "redirect_uri" field to the value that was provided on create.
func (u *CodeUpsertBulk) UpdateRedirectURI() *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateRedirectURI()
	})
}

// SetExpiresAt sets the "expires_at" field.
func (u *CodeUpsertBulk) SetExpiresAt(v time.Time) *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.SetExpiresAt(v)
	})
}

// UpdateExpiresAt sets the "expires_at" field to the value that was provided on create.
func (u *CodeUpsertBulk) UpdateExpiresAt() *CodeUpsertBulk {
	return u.Update(func(s *CodeUpsert) {
		s.UpdateExpiresAt()
	})
}

// Exec executes the query.
func (u *CodeUpsertBulk) Exec(ctx context.Context) error {
	if u.create.err != nil {
		return u.create.err
	}
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the CodeCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for CodeCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *CodeUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
