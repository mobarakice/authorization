# Following are the dummy dataset

### Resources

| Resource name | Description                                                    |
|---------------|----------------------------------------------------------------|
| **Flight**    | Aireline operation on spesific route. exe.Flight 101: DAC->CGP |
| **PNR**       | Passenger Name Record                                          |
| **PNL**       | Passenger Name Locator/List                                    |
| **Price**     | Price for a ticket                                             |
| **Sales**     | Sales and marketing                                            |

### Action

| Action name       | Description                |
|-------------------|----------------------------|
| **Create**        | can create new record      |
| **Update**        | can update existing record |
| **Read**          | only view/read             |
| **Delete**        | can delete a record        |

### Roles

| Role name             | Description                 |
|-----------------------|-----------------------------|
| **Supper Admin**      | System Admin                |
| **Admin**             | An executive                |
| **Support Executive** | Support                     |
| **Booking Agent**     | Reservation agent           |
| **Sale Excutive**     | Sales and marketing officer |

### Role permissions

| Role name             | Resource and Action                                                |
|-----------------------|--------------------------------------------------------------------|
| **Supper Admin**      | Flight, PNR, PNL, Price, Sales(All-> Create, Update, Read, Delete) |
| **Admin**             | Flight, Price, Sales (All-> Create, Update, Read, Delete)          |
| **Support Executive** | Flight, PNL(Read)                                                  |
| **Booking Agent**     | Flight(Read), PNR(All->Create, Update, Read, Delete)               |              |
| **Sale Excutive**     | Price, Salse (All-> Create, Update, Read, Delete)                  |

### User with Role and extra permission

| User          | Role             | Extra permission |
|---------------|------------------|------------------|
| **Mobarak**   | Supper Admin     | -                |
| **Mahtab**    | Admin            | -                |
| **Shamim**    | Admin            | Price->Block     |
| **Alamin**    | Support Excutive    | PNL->Block       |
| **Hasbullah** | Support Excutive    | Price(Read)      |
| **Nafi**      | Booking Agent    | -                |
| **Nahian**    | Sale Excutive | PNR(Read)        |
| **Kiron**     | Sale Excutive | -                |