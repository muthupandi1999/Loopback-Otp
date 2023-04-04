#TODO: Remove these scripts from the repo once the relations are updated in Model.
create table Review
(
    id           int auto_increment,
    userId       int, #reviewer
    isAnonymous  bool,
    rating       int,
    employeeId   int, #Reviewee
    isActive     bool,
    review       varchar(500),
    updated_date datetime,
    created_date datetime,
    isRemoved    bool,
    constraint Review_pk primary key (id),
    constraint review_user_id_fk foreign key (userId) references User (id),
    constraint review_employee_id_fk foreign key (employeeId) references Labor (id)
);
