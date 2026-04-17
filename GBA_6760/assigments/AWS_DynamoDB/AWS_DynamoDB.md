# Introduction to Amazon DynamoDB (Lab Notes)

## Overview

DynamoDB is a **fully managed NoSQL database** that supports:

* **Key-value + document data models**
* **Single-digit millisecond latency**
* **Automatic scaling**

Used for:

* Web/mobile apps
* Gaming
* IoT
* High-scale systems

## Core Concepts

### Table

* Collection of items (like a table in SQL)
* Must define a **Primary Key**

### Item

* A single record (like a row)
* Made up of attributes

### Attribute

* Key-value pair (like a column)
* Can differ per item (schema-less)

## Keys (IMPORTANT)

### Partition Key (Primary Key)

* Required
* Used to distribute data
* Example: `Artist`

### Sort Key (Optional)

* Used with partition key
* Enables multiple items per partition
* Example: `Song`

### Composite Key

```
Partition Key + Sort Key → uniquely identifies item
```

## Schema Behavior (THIS IS TESTED)

* DynamoDB is **schema-less**
* Only required fields:

  * Partition Key
  * Sort Key (if defined)

### Important Rule

* Items **can have different attributes**

Example:

```
Item 1 → Artist, Song, Album, Year
Item 2 → Artist, Song, Genre
Item 3 → Artist, Song, LengthSeconds
```

## Creating a Table (Lab)

Table:

```
Name: Music
Partition Key: Artist (String)
Sort Key: Song (String)
```

* Defaults used for capacity/indexes
* Wait until status = **Active**

## Adding Data

### Required fields:

* Partition Key
* Sort Key (if used)

### Example Item

```
Artist: Pink Floyd
Song: Money
Album: The Dark Side of the Moon
Year: 1973
```

### Key Takeaway

* You can add **new attributes anytime**
* No schema update required

## Updating Data

* Select item → Edit
* Modify attribute (e.g., Year 2011 → 2012)
* Save

## Query vs Scan (VERY IMPORTANT)

### Query (Preferred)

* Uses **Primary Key**
* Fast (indexed)
* Example:

```
Artist = Psy
Song = Gangnam Style
```

### Scan

* Reads **entire table**
* Slower and inefficient
* Use only when necessary

## Key Difference

```
Query → targeted (fast)
Scan  → full table (slow)
```

## Retrieving Data (Exam Concepts)

* **Query** → specific criteria (best answer)
* **Scan** → brute force
* **GetItem** → exact primary key lookup

## Deleting a Table

* Deletes:

  * Table
  * ALL data

### Critical Consideration

* **Back up data before deletion**

## Lab Flow (What You Actually Did)

```
1. Create table (Music)
2. Insert items
3. Modify item
4. Query table
5. Scan table
6. Delete table
```

## Common DynamoDB Gotchas

* No fixed schema → flexibility
* Only keys are required
* Query requires partition key
* Scan is expensive
* Deleting table = permanent

## Knowledge Check (What They Tested You On)

* Schema flexibility
* Items can have different attributes
* Composite key = unique identifier
* Query vs Scan difference
* Backups before deletion

## Mental Model

Think of DynamoDB like:

```
A flexible JSON store
where only the ID (key) matters
```

