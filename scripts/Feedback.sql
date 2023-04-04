#TODO: Remove these scripts from the repo once the relations are updated in Model.

create table FeedbackMaster
(
    id          int auto_increment,
    type        varchar(100) not null,
    description varchar(500) null,
    constraint FeedbackMaster_pk
        primary key (id)
);

create table Feedback
(
    id         int             NOT NULL AUTO_INCREMENT,
    userId     int             NOT NULL,
    feedbackId int             null,
    message    multilinestring not null,
    createdOn  datetime        null,
    constraint feedback_pk
        primary key (id),
    constraint feedback_user_id_fk
        foreign key (userId) references User (id)
);

#INSERT INTO FeedbackMaster(type, description) VALUES("Support","Please tell us how can we help you");
#INSERT INTO FeedbackMaster(type, description) VALUES("Advertise with us","Please tell us how can we help you");
#INSERT INTO FeedbackMaster(type, description) VALUES("Sales","Please tell us how can we help you");
#INSERT INTO FeedbackMaster(type, description) VALUES("Other","Please tell us how can we help you");
