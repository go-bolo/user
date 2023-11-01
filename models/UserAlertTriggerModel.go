package user_models

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/helpers"
	"github.com/labstack/echo/v4"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserAlertTriggerModel - Model to store user alerts
type UserAlertTriggerModel struct {
	ID              uint64         `gorm:"primary_key" json:"id"`
	Name            string         `gorm:"column:name;" json:"name"`
	UserDisplayName string         `gorm:"column:userDisplayName;" json:"userDisplayName"`
	Whatsapp        string         `gorm:"column:whatsapp;" json:"whatsapp"`
	Emails          string         `gorm:"column:emails;type:TEXT;" json:"emails"`
	Weight          int            `gorm:"column:weight;" json:"weight"`
	Type            string         `gorm:"column:type;" json:"type"`
	ProcessData     datatypes.JSON `gorm:"column:processData;" json:"processData"`
	Published       bool           `gorm:"column:published;" json:"published"`

	CreatorId int `gorm:"column:creatorId;type:int(11);" json:"creatorId"`

	CreatedAt time.Time  `gorm:"column:createdAt;" sql:"DEFAULT:'current_timestamp'" json:"createdAt"`
	UpdatedAt *time.Time `gorm:"column:updatedAt;" json:"updatedAt"`
}

type UserAlertTriggerModelProcessDataType struct {
	Symbols []string
}

// TableName ...
func (r *UserAlertTriggerModel) TableName() string {
	return "user_alert_triggers"
}

func (r *UserAlertTriggerModel) GetID() string {
	return strconv.FormatUint(r.ID, 10)
}

func UserTriggerFindOne(id string, record *UserAlertTriggerModel) error {
	db := bolo.GetDefaultDatabaseConnection()
	err := db.First(record, id).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}
	return nil
}

func (r *UserAlertTriggerModel) GetSymbolsCount() int {
	var alertSymbolsList UserAlertTriggerModelProcessDataType
	processData, _ := r.ProcessData.MarshalJSON()

	if err := json.Unmarshal(processData, &alertSymbolsList); err != nil {
		return 0
	}

	return len(alertSymbolsList.Symbols)
}

func (r *UserAlertTriggerModel) GetSymbolsToProcess() UserAlertTriggerModelProcessDataType {
	var alertSymbolsList UserAlertTriggerModelProcessDataType
	processData, _ := r.ProcessData.MarshalJSON()

	if err := json.Unmarshal(processData, &alertSymbolsList); err != nil {
		return alertSymbolsList
	}

	for i := range alertSymbolsList.Symbols {
		alertSymbolsList.Symbols[i] = strings.Replace(alertSymbolsList.Symbols[i], "BVMF:", "", 1)
	}

	return alertSymbolsList
}

func FindOneAlertToProcess(alertId int, r *UserAlertTriggerModel) error {
	var err error
	db := bolo.GetDefaultDatabaseConnection()

	if err = db.
		Order("weight DESC").
		Where("id = ?", alertId).
		Find(&r).Error; err != nil {

		if err != gorm.ErrRecordNotFound {
			return err
		}
	}

	return nil
}

func FindOneAlertByUserId(userId int, r *UserAlertTriggerModel) error {
	var err error
	db := bolo.GetDefaultDatabaseConnection()

	if err = db.
		Order("weight DESC").
		Where("type = 'symbol-price-change' AND creatorId = ?", userId).
		Find(&r).Error; err != nil {

		if err != gorm.ErrRecordNotFound {
			return err
		}
	}

	return nil
}

func FindAllTrigers(target *[]UserAlertTriggerModel) error {
	db := bolo.GetDefaultDatabaseConnection()

	if err := db.
		// Select([]string{"ult", "date"}).
		// Where("published = ?", true).
		Order("id ASC").
		Limit(20000).
		Find(target).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return err
		}
		return err
	}

	return nil
}

func (r *UserAlertTriggerModel) LoadData() error {

	r.GetID()
	return nil
}

func (r *UserAlertTriggerModel) LoadTeaserData() error {
	r.GetID()
	return nil
}

func (r *UserAlertTriggerModel) Save() error {
	var err error
	db := bolo.GetDefaultDatabaseConnection()

	if r.ID == 0 {
		// create ....
		err = db.Create(&r).Error
		if err != nil {
			return err
		}
	} else {
		// update ...
		err = db.Save(&r).Error
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *UserAlertTriggerModel) Delete() error {
	if r.ID == 0 {
		return nil
	}
	db := bolo.GetDefaultDatabaseConnection()
	return db.Unscoped().Delete(&r).Error
}

type UserAlertTriggerQueryAndCounttCfg struct {
	Records *[]*UserAlertTriggerModel
	Count   *int64
	Limit   int
	Offset  int
	C       echo.Context
	IsHTML  bool
}

func UserAlertTriggerQueryAndCountFromRequest(opts *UserAlertTriggerQueryAndCounttCfg) error {
	db := bolo.GetDefaultDatabaseConnection()

	c := opts.C

	q := c.QueryParam("q")
	query := db
	ctx := c.(*bolo.RequestContext)

	can := ctx.Can("find_user")
	if !can {
		logrus.WithFields(logrus.Fields{
			"roles": ctx.GetAuthenticatedRoles(),
		}).Debug("QueryAndCountFromRequest forbidden")

		return nil
	}

	queryI, err := ctx.Query.SetDatabaseQueryForModel(query, &UserAlertTriggerModel{})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": fmt.Sprintf("%+v\n", err),
		}).Error("QueryAndCountFromRequest error")
	}
	query = queryI.(*gorm.DB)

	if q != "" {
		query = query.Where(
			db.Where("displayName LIKE ?", "%"+q+"%").Or(db.Where("fullName LIKE ?", "%"+q+"%")),
		)
	}

	orderColumn, orderIsDesc, orderValid := helpers.ParseUrlQueryOrder(c.QueryParam("order"), c.QueryParam("sort"), c.QueryParam("sortDirection"))

	if orderValid {
		query = query.Order(clause.OrderByColumn{
			Column: clause.Column{Table: clause.CurrentTable, Name: orderColumn},
			Desc:   orderIsDesc,
		})
	} else {
		query = query.Order("createdAt DESC").
			Order("id DESC")
	}

	query = query.Limit(opts.Limit).
		Offset(opts.Offset)

	r := query.Find(opts.Records)
	if r.Error != nil {
		return errors.Wrap(r.Error, "userAlertTrigger.QueryAndCountFromRequest error on find records")
	}

	return UserAlertTriggerCountQueryFromRequest(opts)
}

func UserAlertTriggerCountQueryFromRequest(opts *UserAlertTriggerQueryAndCounttCfg) error {
	db := bolo.GetDefaultDatabaseConnection()

	c := opts.C
	q := c.QueryParam("q")
	ctx := c.(*bolo.RequestContext)

	// Count ...
	queryCount := db

	if q != "" {
		queryCount = queryCount.Or(
			db.Where("displayName LIKE ?", "%"+q+"%"),
			db.Where("fullName LIKE ?", "%"+q+"%"),
		)
	}

	can := ctx.Can("find_user")
	if !can {
		return nil
	}

	queryICount, err := ctx.Query.SetDatabaseQueryForModel(queryCount, &UserAlertTriggerModel{})
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"error": fmt.Sprintf("%+v\n", err),
		}).Error("QueryAndCountFromRequest count error")
	}
	queryCount = queryICount.(*gorm.DB)

	return queryCount.
		Table("user_alert_triggers").
		Count(opts.Count).Error
}
