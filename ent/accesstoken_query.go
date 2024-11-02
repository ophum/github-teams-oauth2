// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"fmt"
	"math"

	"entgo.io/ent"
	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/ophum/github-teams-oauth2/ent/accesstoken"
	"github.com/ophum/github-teams-oauth2/ent/predicate"
)

// AccessTokenQuery is the builder for querying AccessToken entities.
type AccessTokenQuery struct {
	config
	ctx        *QueryContext
	order      []accesstoken.OrderOption
	inters     []Interceptor
	predicates []predicate.AccessToken
	// intermediate query (i.e. traversal path).
	sql  *sql.Selector
	path func(context.Context) (*sql.Selector, error)
}

// Where adds a new predicate for the AccessTokenQuery builder.
func (atq *AccessTokenQuery) Where(ps ...predicate.AccessToken) *AccessTokenQuery {
	atq.predicates = append(atq.predicates, ps...)
	return atq
}

// Limit the number of records to be returned by this query.
func (atq *AccessTokenQuery) Limit(limit int) *AccessTokenQuery {
	atq.ctx.Limit = &limit
	return atq
}

// Offset to start from.
func (atq *AccessTokenQuery) Offset(offset int) *AccessTokenQuery {
	atq.ctx.Offset = &offset
	return atq
}

// Unique configures the query builder to filter duplicate records on query.
// By default, unique is set to true, and can be disabled using this method.
func (atq *AccessTokenQuery) Unique(unique bool) *AccessTokenQuery {
	atq.ctx.Unique = &unique
	return atq
}

// Order specifies how the records should be ordered.
func (atq *AccessTokenQuery) Order(o ...accesstoken.OrderOption) *AccessTokenQuery {
	atq.order = append(atq.order, o...)
	return atq
}

// First returns the first AccessToken entity from the query.
// Returns a *NotFoundError when no AccessToken was found.
func (atq *AccessTokenQuery) First(ctx context.Context) (*AccessToken, error) {
	nodes, err := atq.Limit(1).All(setContextOp(ctx, atq.ctx, ent.OpQueryFirst))
	if err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, &NotFoundError{accesstoken.Label}
	}
	return nodes[0], nil
}

// FirstX is like First, but panics if an error occurs.
func (atq *AccessTokenQuery) FirstX(ctx context.Context) *AccessToken {
	node, err := atq.First(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return node
}

// FirstID returns the first AccessToken ID from the query.
// Returns a *NotFoundError when no AccessToken ID was found.
func (atq *AccessTokenQuery) FirstID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = atq.Limit(1).IDs(setContextOp(ctx, atq.ctx, ent.OpQueryFirstID)); err != nil {
		return
	}
	if len(ids) == 0 {
		err = &NotFoundError{accesstoken.Label}
		return
	}
	return ids[0], nil
}

// FirstIDX is like FirstID, but panics if an error occurs.
func (atq *AccessTokenQuery) FirstIDX(ctx context.Context) int {
	id, err := atq.FirstID(ctx)
	if err != nil && !IsNotFound(err) {
		panic(err)
	}
	return id
}

// Only returns a single AccessToken entity found by the query, ensuring it only returns one.
// Returns a *NotSingularError when more than one AccessToken entity is found.
// Returns a *NotFoundError when no AccessToken entities are found.
func (atq *AccessTokenQuery) Only(ctx context.Context) (*AccessToken, error) {
	nodes, err := atq.Limit(2).All(setContextOp(ctx, atq.ctx, ent.OpQueryOnly))
	if err != nil {
		return nil, err
	}
	switch len(nodes) {
	case 1:
		return nodes[0], nil
	case 0:
		return nil, &NotFoundError{accesstoken.Label}
	default:
		return nil, &NotSingularError{accesstoken.Label}
	}
}

// OnlyX is like Only, but panics if an error occurs.
func (atq *AccessTokenQuery) OnlyX(ctx context.Context) *AccessToken {
	node, err := atq.Only(ctx)
	if err != nil {
		panic(err)
	}
	return node
}

// OnlyID is like Only, but returns the only AccessToken ID in the query.
// Returns a *NotSingularError when more than one AccessToken ID is found.
// Returns a *NotFoundError when no entities are found.
func (atq *AccessTokenQuery) OnlyID(ctx context.Context) (id int, err error) {
	var ids []int
	if ids, err = atq.Limit(2).IDs(setContextOp(ctx, atq.ctx, ent.OpQueryOnlyID)); err != nil {
		return
	}
	switch len(ids) {
	case 1:
		id = ids[0]
	case 0:
		err = &NotFoundError{accesstoken.Label}
	default:
		err = &NotSingularError{accesstoken.Label}
	}
	return
}

// OnlyIDX is like OnlyID, but panics if an error occurs.
func (atq *AccessTokenQuery) OnlyIDX(ctx context.Context) int {
	id, err := atq.OnlyID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// All executes the query and returns a list of AccessTokens.
func (atq *AccessTokenQuery) All(ctx context.Context) ([]*AccessToken, error) {
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryAll)
	if err := atq.prepareQuery(ctx); err != nil {
		return nil, err
	}
	qr := querierAll[[]*AccessToken, *AccessTokenQuery]()
	return withInterceptors[[]*AccessToken](ctx, atq, qr, atq.inters)
}

// AllX is like All, but panics if an error occurs.
func (atq *AccessTokenQuery) AllX(ctx context.Context) []*AccessToken {
	nodes, err := atq.All(ctx)
	if err != nil {
		panic(err)
	}
	return nodes
}

// IDs executes the query and returns a list of AccessToken IDs.
func (atq *AccessTokenQuery) IDs(ctx context.Context) (ids []int, err error) {
	if atq.ctx.Unique == nil && atq.path != nil {
		atq.Unique(true)
	}
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryIDs)
	if err = atq.Select(accesstoken.FieldID).Scan(ctx, &ids); err != nil {
		return nil, err
	}
	return ids, nil
}

// IDsX is like IDs, but panics if an error occurs.
func (atq *AccessTokenQuery) IDsX(ctx context.Context) []int {
	ids, err := atq.IDs(ctx)
	if err != nil {
		panic(err)
	}
	return ids
}

// Count returns the count of the given query.
func (atq *AccessTokenQuery) Count(ctx context.Context) (int, error) {
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryCount)
	if err := atq.prepareQuery(ctx); err != nil {
		return 0, err
	}
	return withInterceptors[int](ctx, atq, querierCount[*AccessTokenQuery](), atq.inters)
}

// CountX is like Count, but panics if an error occurs.
func (atq *AccessTokenQuery) CountX(ctx context.Context) int {
	count, err := atq.Count(ctx)
	if err != nil {
		panic(err)
	}
	return count
}

// Exist returns true if the query has elements in the graph.
func (atq *AccessTokenQuery) Exist(ctx context.Context) (bool, error) {
	ctx = setContextOp(ctx, atq.ctx, ent.OpQueryExist)
	switch _, err := atq.FirstID(ctx); {
	case IsNotFound(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("ent: check existence: %w", err)
	default:
		return true, nil
	}
}

// ExistX is like Exist, but panics if an error occurs.
func (atq *AccessTokenQuery) ExistX(ctx context.Context) bool {
	exist, err := atq.Exist(ctx)
	if err != nil {
		panic(err)
	}
	return exist
}

// Clone returns a duplicate of the AccessTokenQuery builder, including all associated steps. It can be
// used to prepare common query builders and use them differently after the clone is made.
func (atq *AccessTokenQuery) Clone() *AccessTokenQuery {
	if atq == nil {
		return nil
	}
	return &AccessTokenQuery{
		config:     atq.config,
		ctx:        atq.ctx.Clone(),
		order:      append([]accesstoken.OrderOption{}, atq.order...),
		inters:     append([]Interceptor{}, atq.inters...),
		predicates: append([]predicate.AccessToken{}, atq.predicates...),
		// clone intermediate query.
		sql:  atq.sql.Clone(),
		path: atq.path,
	}
}

// GroupBy is used to group vertices by one or more fields/columns.
// It is often used with aggregate functions, like: count, max, mean, min, sum.
func (atq *AccessTokenQuery) GroupBy(field string, fields ...string) *AccessTokenGroupBy {
	atq.ctx.Fields = append([]string{field}, fields...)
	grbuild := &AccessTokenGroupBy{build: atq}
	grbuild.flds = &atq.ctx.Fields
	grbuild.label = accesstoken.Label
	grbuild.scan = grbuild.Scan
	return grbuild
}

// Select allows the selection one or more fields/columns for the given query,
// instead of selecting all fields in the entity.
func (atq *AccessTokenQuery) Select(fields ...string) *AccessTokenSelect {
	atq.ctx.Fields = append(atq.ctx.Fields, fields...)
	sbuild := &AccessTokenSelect{AccessTokenQuery: atq}
	sbuild.label = accesstoken.Label
	sbuild.flds, sbuild.scan = &atq.ctx.Fields, sbuild.Scan
	return sbuild
}

// Aggregate returns a AccessTokenSelect configured with the given aggregations.
func (atq *AccessTokenQuery) Aggregate(fns ...AggregateFunc) *AccessTokenSelect {
	return atq.Select().Aggregate(fns...)
}

func (atq *AccessTokenQuery) prepareQuery(ctx context.Context) error {
	for _, inter := range atq.inters {
		if inter == nil {
			return fmt.Errorf("ent: uninitialized interceptor (forgotten import ent/runtime?)")
		}
		if trv, ok := inter.(Traverser); ok {
			if err := trv.Traverse(ctx, atq); err != nil {
				return err
			}
		}
	}
	for _, f := range atq.ctx.Fields {
		if !accesstoken.ValidColumn(f) {
			return &ValidationError{Name: f, err: fmt.Errorf("ent: invalid field %q for query", f)}
		}
	}
	if atq.path != nil {
		prev, err := atq.path(ctx)
		if err != nil {
			return err
		}
		atq.sql = prev
	}
	return nil
}

func (atq *AccessTokenQuery) sqlAll(ctx context.Context, hooks ...queryHook) ([]*AccessToken, error) {
	var (
		nodes = []*AccessToken{}
		_spec = atq.querySpec()
	)
	_spec.ScanValues = func(columns []string) ([]any, error) {
		return (*AccessToken).scanValues(nil, columns)
	}
	_spec.Assign = func(columns []string, values []any) error {
		node := &AccessToken{config: atq.config}
		nodes = append(nodes, node)
		return node.assignValues(columns, values)
	}
	for i := range hooks {
		hooks[i](ctx, _spec)
	}
	if err := sqlgraph.QueryNodes(ctx, atq.driver, _spec); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nodes, nil
	}
	return nodes, nil
}

func (atq *AccessTokenQuery) sqlCount(ctx context.Context) (int, error) {
	_spec := atq.querySpec()
	_spec.Node.Columns = atq.ctx.Fields
	if len(atq.ctx.Fields) > 0 {
		_spec.Unique = atq.ctx.Unique != nil && *atq.ctx.Unique
	}
	return sqlgraph.CountNodes(ctx, atq.driver, _spec)
}

func (atq *AccessTokenQuery) querySpec() *sqlgraph.QuerySpec {
	_spec := sqlgraph.NewQuerySpec(accesstoken.Table, accesstoken.Columns, sqlgraph.NewFieldSpec(accesstoken.FieldID, field.TypeInt))
	_spec.From = atq.sql
	if unique := atq.ctx.Unique; unique != nil {
		_spec.Unique = *unique
	} else if atq.path != nil {
		_spec.Unique = true
	}
	if fields := atq.ctx.Fields; len(fields) > 0 {
		_spec.Node.Columns = make([]string, 0, len(fields))
		_spec.Node.Columns = append(_spec.Node.Columns, accesstoken.FieldID)
		for i := range fields {
			if fields[i] != accesstoken.FieldID {
				_spec.Node.Columns = append(_spec.Node.Columns, fields[i])
			}
		}
	}
	if ps := atq.predicates; len(ps) > 0 {
		_spec.Predicate = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	if limit := atq.ctx.Limit; limit != nil {
		_spec.Limit = *limit
	}
	if offset := atq.ctx.Offset; offset != nil {
		_spec.Offset = *offset
	}
	if ps := atq.order; len(ps) > 0 {
		_spec.Order = func(selector *sql.Selector) {
			for i := range ps {
				ps[i](selector)
			}
		}
	}
	return _spec
}

func (atq *AccessTokenQuery) sqlQuery(ctx context.Context) *sql.Selector {
	builder := sql.Dialect(atq.driver.Dialect())
	t1 := builder.Table(accesstoken.Table)
	columns := atq.ctx.Fields
	if len(columns) == 0 {
		columns = accesstoken.Columns
	}
	selector := builder.Select(t1.Columns(columns...)...).From(t1)
	if atq.sql != nil {
		selector = atq.sql
		selector.Select(selector.Columns(columns...)...)
	}
	if atq.ctx.Unique != nil && *atq.ctx.Unique {
		selector.Distinct()
	}
	for _, p := range atq.predicates {
		p(selector)
	}
	for _, p := range atq.order {
		p(selector)
	}
	if offset := atq.ctx.Offset; offset != nil {
		// limit is mandatory for offset clause. We start
		// with default value, and override it below if needed.
		selector.Offset(*offset).Limit(math.MaxInt32)
	}
	if limit := atq.ctx.Limit; limit != nil {
		selector.Limit(*limit)
	}
	return selector
}

// AccessTokenGroupBy is the group-by builder for AccessToken entities.
type AccessTokenGroupBy struct {
	selector
	build *AccessTokenQuery
}

// Aggregate adds the given aggregation functions to the group-by query.
func (atgb *AccessTokenGroupBy) Aggregate(fns ...AggregateFunc) *AccessTokenGroupBy {
	atgb.fns = append(atgb.fns, fns...)
	return atgb
}

// Scan applies the selector query and scans the result into the given value.
func (atgb *AccessTokenGroupBy) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, atgb.build.ctx, ent.OpQueryGroupBy)
	if err := atgb.build.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AccessTokenQuery, *AccessTokenGroupBy](ctx, atgb.build, atgb, atgb.build.inters, v)
}

func (atgb *AccessTokenGroupBy) sqlScan(ctx context.Context, root *AccessTokenQuery, v any) error {
	selector := root.sqlQuery(ctx).Select()
	aggregation := make([]string, 0, len(atgb.fns))
	for _, fn := range atgb.fns {
		aggregation = append(aggregation, fn(selector))
	}
	if len(selector.SelectedColumns()) == 0 {
		columns := make([]string, 0, len(*atgb.flds)+len(atgb.fns))
		for _, f := range *atgb.flds {
			columns = append(columns, selector.C(f))
		}
		columns = append(columns, aggregation...)
		selector.Select(columns...)
	}
	selector.GroupBy(selector.Columns(*atgb.flds...)...)
	if err := selector.Err(); err != nil {
		return err
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := atgb.build.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}

// AccessTokenSelect is the builder for selecting fields of AccessToken entities.
type AccessTokenSelect struct {
	*AccessTokenQuery
	selector
}

// Aggregate adds the given aggregation functions to the selector query.
func (ats *AccessTokenSelect) Aggregate(fns ...AggregateFunc) *AccessTokenSelect {
	ats.fns = append(ats.fns, fns...)
	return ats
}

// Scan applies the selector query and scans the result into the given value.
func (ats *AccessTokenSelect) Scan(ctx context.Context, v any) error {
	ctx = setContextOp(ctx, ats.ctx, ent.OpQuerySelect)
	if err := ats.prepareQuery(ctx); err != nil {
		return err
	}
	return scanWithInterceptors[*AccessTokenQuery, *AccessTokenSelect](ctx, ats.AccessTokenQuery, ats, ats.inters, v)
}

func (ats *AccessTokenSelect) sqlScan(ctx context.Context, root *AccessTokenQuery, v any) error {
	selector := root.sqlQuery(ctx)
	aggregation := make([]string, 0, len(ats.fns))
	for _, fn := range ats.fns {
		aggregation = append(aggregation, fn(selector))
	}
	switch n := len(*ats.selector.flds); {
	case n == 0 && len(aggregation) > 0:
		selector.Select(aggregation...)
	case n != 0 && len(aggregation) > 0:
		selector.AppendSelect(aggregation...)
	}
	rows := &sql.Rows{}
	query, args := selector.Query()
	if err := ats.driver.Query(ctx, query, args, rows); err != nil {
		return err
	}
	defer rows.Close()
	return sql.ScanSlice(rows, v)
}
