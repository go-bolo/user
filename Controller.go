package user

import (
	"net/http"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/acl"
	"github.com/labstack/echo/v4"
	gonanoid "github.com/matoous/go-nanoid"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"go.uber.org/zap"
)

var userControllerLogPrefix = "user.controller."

type ListJSONResponse struct {
	bolo.BaseListReponse
	Record *[]*UserModel `json:"user"`
}

type CountJSONResponse struct {
	bolo.BaseMetaResponse
}

type FindOneJSONResponse struct {
	Record *UserModel `json:"user"`
}

type RequestBody struct {
	Record *UserModel `json:"user"`
}

type TeaserTPL struct {
	Ctx    echo.Context
	Record *UserModel
}

// Http user controller | struct with http handlers
type Controller struct{}

func (ctl *Controller) Find(c echo.Context) (bolo.Response, error) {
	var err error
	pager := bolo.GetPager(c)
	l := bolo.GetLogger(c)

	var count int64
	records := []*UserModel{}
	err = QueryAndCountFromRequest(&QueryAndCountFromRequestCfg{
		Records: &records,
		Count:   &count,
		Limit:   int(pager.Limit),
		Offset:  bolo.GetOffset(c),
		C:       c,
	})
	if err != nil {
		l.Debug(userControllerLogPrefix+" query Error on find users", zap.Error(err))
	}

	pager.Count = count

	l.Debug(userControllerLogPrefix+" query count result", zap.Int64("count", count), zap.Int("len_records_found", len(records)))

	for i := range records {
		records[i].LoadData()
	}

	resp := ListJSONResponse{
		Record: &records,
	}

	resp.Meta.Count = count

	return &bolo.DefaultResponse{
		Data: resp,
	}, nil
}

func (ctl *Controller) Create(c echo.Context) (bolo.Response, error) {
	l := bolo.GetLogger(c)
	l.Debug(userControllerLogPrefix + "create running")

	var err error
	app := bolo.GetApp(c)

	can := bolo.Can(c, "create_user")
	if !can {
		return nil, bolo.NewHTTPError(http.StatusForbidden, "Forbidden", nil)
	}

	var body RequestBody

	if err := c.Bind(&body); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return nil, err
		}
		return &bolo.DefaultResponse{Status: http.StatusNotFound}, nil
	}

	record := body.Record
	record.ID = 0

	if record.Username == "" {
		record.Username, err = gonanoid.Nanoid()
		if err != nil {
			return nil, err
		}
	}

	if err := c.Validate(record); err != nil {
		if _, ok := err.(*echo.HTTPError); ok {
			return nil, err
		}
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"body": body,
	}).Debug(userControllerLogPrefix + "create params")

	err = record.Save(app)
	if err != nil {
		return nil, err
	}

	err = record.LoadData()
	if err != nil {
		return nil, err
	}

	resp := FindOneJSONResponse{
		Record: record,
	}

	return &bolo.DefaultResponse{
		Status: http.StatusCreated,
		Data:   resp,
	}, nil
}

func (ctl *Controller) Count(c echo.Context) (bolo.Response, error) {
	var err error
	pager := bolo.GetPager(c)
	l := bolo.GetLogger(c)
	l.Debug(userControllerLogPrefix + "create running")

	var count int64
	err = CountQueryFromRequest(&QueryAndCountFromRequestCfg{
		Count:  &count,
		Limit:  int(pager.Limit),
		Offset: bolo.GetOffset(c),
		C:      c,
	})

	if err != nil {
		l.Debug(userControllerLogPrefix+"count Error on find users", zap.Error(err))
		return nil, err
	}

	pager.Count = count

	resp := CountJSONResponse{}
	resp.Count = count

	return &bolo.DefaultResponse{
		Data: resp,
	}, nil
}

func (ctl *Controller) FindOne(c echo.Context) (bolo.Response, error) {
	id := c.Param("id")
	l := bolo.GetLogger(c)
	l.Debug(userControllerLogPrefix+"findOne id from params", zap.String("id", id))
	app := bolo.GetApp(c)

	record := UserModel{}
	err := UserFindOne(app, id, &record)
	if err != nil {
		return nil, err
	}

	if record.ID == 0 {
		l.Debug(userControllerLogPrefix+"findOne id record not found", zap.String("id", id))
		return nil, bolo.NewHTTPError(http.StatusNotFound, "Not found", nil)
	}

	if bolo.IsAuthenticated(c) {
		if record.GetID() == bolo.GetAuthenticatedUser(c).GetID() {
			bolo.AddRole(c, "owner")
		}
	}

	can := bolo.Can(c, "read_user")
	if !can {
		return nil, bolo.NewHTTPError(403, "Forbidden", errors.New("user.FindOne forbidden"))
	}

	record.LoadData()

	resp := FindOneJSONResponse{
		Record: &record,
	}

	return &bolo.DefaultResponse{
		Data: resp,
	}, nil
}

func (ctl *Controller) Update(c echo.Context) (bolo.Response, error) {
	var err error
	app := bolo.GetApp(c)
	l := bolo.GetLogger(c)
	id := c.Param("id")

	record := UserModel{}
	err = UserFindOne(app, id, &record)
	if err != nil {
		l.Debug(userControllerLogPrefix+"update error on find one", zap.Error(err), zap.String("id", id))
		return nil, errors.Wrap(err, userControllerLogPrefix+"update error on find one")
	}

	if bolo.IsAuthenticated(c) {
		if record.GetID() == bolo.GetAuthenticatedUser(c).GetID() {
			bolo.AddRole(c, "owner")
		}
	}

	if !bolo.Can(c, "update_user") {
		return nil, bolo.NewHTTPError(http.StatusForbidden, "Forbidden", nil)
	}

	record.LoadData()

	body := FindOneJSONResponse{Record: &record}

	if err := c.Bind(&body); err != nil {
		l.Debug(userControllerLogPrefix+"update error on bind", zap.Error(err), zap.String("id", id))

		if _, ok := err.(*echo.HTTPError); ok {
			return nil, err
		}
		return nil, c.NoContent(http.StatusNotFound)
	}

	err = record.Save(app)
	if err != nil {
		return nil, err
	}

	return &bolo.DefaultResponse{
		Data: FindOneJSONResponse{
			Record: &record,
		},
	}, nil
}

func (ctl *Controller) Delete(c echo.Context) (bolo.Response, error) {
	var err error
	l := bolo.GetLogger(c)
	id := c.Param("id")
	app := bolo.GetApp(c)

	l.Debug(userControllerLogPrefix+"delete id from params", zap.String("id", id))

	record := UserModel{}
	err = UserFindOne(app, id, &record)
	if err != nil {
		return nil, err
	}

	if record.ID == 0 {
		return nil, bolo.NewHTTPError(http.StatusNotFound, "Not found", nil)
	}

	if bolo.IsAuthenticated(c) {
		if record.GetID() == bolo.GetAuthenticatedUser(c).GetID() {
			bolo.AddRole(c, "owner")
		}
	}

	if !bolo.Can(c, "delete_user") {
		return nil, bolo.NewHTTPError(http.StatusForbidden, "Forbidden", nil)
	}

	err = record.Delete(app)
	if err != nil {
		return nil, err
	}

	return &bolo.DefaultResponse{
		Status: http.StatusNotFound,
	}, nil
}

// func (ctl *Controller) FindAllPageHandler(c echo.Context) error {
// 	var err error
// 	ctx := c.(*catu.RequestContext)

// 	switch ctx.GetResponseContentType() {
// 	case "application/json":
// 		return ctl.Query(c)
// 	}

// 	ctx.Title = "Usuários"
// 	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
// 	mt.Title = "Usuários no Monitor do Mercado"

// 	var count int64
// 	records := []*UserModel{}
// 	err = QueryAndCountFromRequest(&QueryAndCountFromRequestCfg{
// 		Records: &records,
// 		Count:   &count,
// 		Limit:   ctx.GetLimit(),
// 		Offset:  ctx.GetOffset(),
// 		C:       c,
// 		IsHTML:  true,
// 	})
// 	if err != nil {
// 		logrus.WithFields(logrus.Fields{
// 			"error": err,
// 		}).Debug(userControllerLogPrefix + "FindAllPageHandler Error on find contents")
// 	}

// 	ctx.Pager.Count = count

// 	var teaserList []string

// 	logrus.WithFields(logrus.Fields{
// 		"count":             count,
// 		"len_records_found": len(records),
// 	}).Debug(userControllerLogPrefix + "FindAllPageHandler count result")

// 	for i := range records {
// 		records[i].LoadTeaserData()

// 		var teaserHTML bytes.Buffer

// 		err = ctx.RenderTemplate(&teaserHTML, "user/teaser", TeaserTPL{
// 			Ctx:    ctx,
// 			Record: records[i],
// 		})
// 		if err != nil {
// 			logrus.WithFields(logrus.Fields{
// 				"err": err.Error(),
// 			}).Error(userControllerLogPrefix + "FindAllPageHandler error on render teaser")
// 		} else {
// 			teaserList = append(teaserList, teaserHTML.String())
// 		}
// 	}

// 	ctx.Set("hasRecords", true)
// 	ctx.Set("records", teaserList)

// 	return c.Render(http.StatusOK, "user/findAll", &catu.TemplateCTX{
// 		Ctx: ctx,
// 	})
// }

// func (ctl *Controller) FindOnePageHandler(c echo.Context) error {
// 	var err error
// 	ctx := c.(*catu.RequestContext)

// 	switch ctx.GetResponseContentType() {
// 	case "application/json":
// 		return ctl.FindOne(c)
// 	}

// 	id := c.Param("id")

// 	logrus.WithFields(logrus.Fields{
// 		"id": id,
// 	}).Debug(userControllerLogPrefix + "FindOnePageHandler id from params")

// 	record := UserModel{}
// 	err = UserFindOne(id, &record)
// 	if err != nil {

// 	}

// 	if record.ID == 0 {
// 		logrus.WithFields(logrus.Fields{
// 			"id": id,
// 		}).Debug(userControllerLogPrefix + "FindOnePageHandler id record not found")
// 		return echo.NotFoundHandler(c)
// 	}

// 	record.LoadData()

// 	ctx.Title = record.DisplayName
// 	ctx.BodyClass = append(ctx.BodyClass, "body-content-findOne")

// 	mt := c.Get("metatags").(*metatags.HTMLMetaTags)
// 	mt.Title = record.DisplayName
// 	mt.Description = record.Biography

// 	return c.Render(http.StatusOK, "user/findOne", &catu.TemplateCTX{
// 		Ctx:    ctx,
// 		Record: &record,
// 	})
// }

type UserRolesResponse struct {
	Roles       map[string]acl.Role `json:"roles"`
	Permissions string              `json:"permissions"`
}

func (ctl *Controller) GetUserRolesAndPermissions(c echo.Context) (bolo.Response, error) {
	acl := bolo.GetApp(c).GetAcl()
	r := UserRolesResponse{Roles: acl.GetRoles()}
	return &bolo.DefaultResponse{
		Data: r,
	}, nil
}

func (ctl *Controller) GetUserRoles(c echo.Context) error {
	return c.String(http.StatusNotImplemented, "Not implemented")
}

type UserRolesBodyRequest struct {
	UserRoles []string `json:"userRoles"`
}

func (ctl *Controller) UpdateUserRoles(c echo.Context) (bolo.Response, error) {
	userID := c.Param("userID")
	app := bolo.GetApp(c)

	var user UserModel
	err := UserFindOne(app, userID, &user)
	if err != nil {
		return nil, err
	}

	if user.ID == 0 {
		return nil, &bolo.HTTPError{
			Code:    404,
			Message: "not found",
		}
	}

	body := UserRolesBodyRequest{}

	if err := c.Bind(&body); err != nil {
		logrus.WithFields(logrus.Fields{
			"error": err,
		}).Debug("user.UpdateUserRoles error on bind")

		if _, ok := err.(*echo.HTTPError); ok {
			return nil, err
		}

		return nil, bolo.NewHTTPError(http.StatusNotFound, "Not found", nil)
	}

	err = user.SetRoles(body.UserRoles)
	if err != nil {
		return nil, err
	}

	err = user.Save(app)
	if err != nil {
		return nil, errors.Wrap(err, "user.UpdateUserRoles error on save user roles")
	}

	return &bolo.DefaultResponse{
		Data: make(map[string]string),
	}, nil
}

type ControllerCfg struct{}

func NewController(cfg *ControllerCfg) *Controller {
	ctx := Controller{}

	return &ctx
}

type RoleTableItem struct {
	Name    string `json:"name"`
	Checked bool   `json:"checked"`
	Role    string `json:"role"`
}
